import time
import psutil
import os
import json
from threading import Thread, Event
from argon2 import PasswordHasher
from argon2.low_level import Type

# ---------------- CONSTANTS ----------------
DUMMY_PASSWORD = "sAMp1ep@ssw0rD:_T35t"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROFILES_FILE = os.path.join(SCRIPT_DIR, "argon2_profiles.json")
MEMORY_SAFETY_RATIO = 0.85
TUNING_EPSILON = 0.05
MAX_TUNE_ITER = 100
COARSE_DOWN_FACTOR = 0.98
MIN_MEM_STEP_KIB = 1024
MAX_PROFILES = 10
DEFAULT_PROFILE_NUMBER = 0
DEFAULT_PROFILE_NAME = "default"
DEFAULT_PROFILE_PARAMS = {
    "time_cost": 3,
    "memory_cost_kib": 65_536,  # 64 MiB
    "parallelism": 2,
    "hash_len": 32,
    "salt_len": 16
}

# Oscillation detection
OSCILLATION_THRESHOLD = 5  # Number of direction changes before triggering damping


# ---------------- HELPERS ----------------
def type_validated_input(prompt: str, expected_type, error_message: str = None, enforce_input: bool = False):
    not_validated = True
    while not_validated:
        value = input(prompt)
        if enforce_input and not value:
            print("Input cannot be empty. Please try again.")
            continue
        elif value:
            try:
                parsed_value = expected_type(value)
                not_validated = False
                return parsed_value
            except (ValueError, TypeError):
                if error_message:
                    print(error_message)
                else:
                    print(f"Invalid input. Expected {expected_type.__name__}. Please try again.")
        else:
            return None


def clamp_parallelism(p):
    return max(1, p)


def available_memory_kib():
    return psutil.virtual_memory().available // 1024


def ensure_memory_safe(memory_cost_kib):
    max_allowed = int(available_memory_kib() * MEMORY_SAFETY_RATIO)
    if memory_cost_kib > max_allowed:
        raise MemoryError(
            f"Requested memory {memory_cost_kib / 1024:.1f} MiB exceeds safe limit {max_allowed / 1024:.1f} MiB"
        )


# ---------------- STARTUP INFO ----------------
def show_system_info():
    vmem = psutil.virtual_memory()
    available_mib = vmem.available / (1024 * 1024)
    recommended_max_mib = available_mib * MEMORY_SAFETY_RATIO
    print(f"\nSystem info:")
    print(f"  Total RAM available: {available_mib:.1f} MiB")
    print(
        f"  Recommended maximum memory cost for testing: {recommended_max_mib:.1f} MiB (~{int(MEMORY_SAFETY_RATIO * 100)}% of available RAM)")


# ---------------- PROFILE HANDLING ----------------
def initialize_profiles():
    profiles = {}
    changed = False
    if os.path.exists(PROFILES_FILE):
        profiles = load_profiles()
    else:
        print(f"\nProfiles file '{PROFILES_FILE}' not found. Creating new one...")
        changed = True

    default_ok = False
    if str(DEFAULT_PROFILE_NUMBER) in profiles:
        entry = profiles[str(DEFAULT_PROFILE_NUMBER)]
        if entry.get("name") == DEFAULT_PROFILE_NAME and entry.get("params") == DEFAULT_PROFILE_PARAMS:
            default_ok = True

    if not default_ok:
        print(f"\nEnsuring default profile exists and is correct...")
        profiles[str(DEFAULT_PROFILE_NUMBER)] = {
            "name": DEFAULT_PROFILE_NAME,
            "params": DEFAULT_PROFILE_PARAMS
        }
        changed = True

    if changed:
        save_profiles(profiles)
    return profiles


def load_profiles():
    try:
        with open(PROFILES_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"⚠ Failed to load {PROFILES_FILE}: {e}")
        return {}


def save_profiles(profiles):
    with open(PROFILES_FILE, "w") as f:
        json.dump(profiles, f, indent=2)
    print(f"\n💾 Profile saved to {PROFILES_FILE}")


def list_profiles(profiles):
    for num_str, entry in sorted(profiles.items(), key=lambda x: int(x[0])):
        print(f"  {num_str}. {entry['name']}")


def select_profile(profiles):
    if not profiles:
        return None, None
    print("\nAvailable profiles:")
    list_profiles(profiles)
    choice = str(type_validated_input("Select profile by number: ", int))
    if choice in profiles:
        return choice, profiles[choice]["params"]
    print("Invalid selection")
    return None, None


def prompt_save_profile(profiles, time_cost, memory_cost_kib, parallelism, hash_len, salt_len):
    choice = type_validated_input("Save profile? (y/n): ", str, enforce_input=True).strip().lower()
    if choice == "y":
        if len(profiles) < MAX_PROFILES:
            profile_name = type_validated_input("Enter profile name to save: ", str)
            if not profile_name:
                print("No name entered. Skipping save.")
                return
        else:
            print("\n⚠ Maximum profiles reached. Choose one to overwrite:")
            list_profiles(profiles)
            sel = type_validated_input("Enter number of profile to overwrite: ", int)
            if sel not in profiles or sel == str(DEFAULT_PROFILE_NUMBER):
                print("Invalid selection or cannot overwrite default. Skipping save.")
                return
            profile_name = type_validated_input("Enter new profile name: ", str, enforce_input=True).strip()
            if not profile_name:
                profile_name = profiles[sel]["name"]
            del profiles[sel]

        # Find first free slot
        for i in range(1, MAX_PROFILES + 1):
            if str(i) not in profiles:
                num_str = str(i)
                break
        else:
            print("No available slot to save profile.")
            return

        profiles[num_str] = {
            "name": profile_name,
            "params": {
                "time_cost": time_cost,
                "memory_cost_kib": memory_cost_kib,
                "parallelism": parallelism,
                "hash_len": hash_len,
                "salt_len": salt_len
            }
        }
        save_profiles(profiles)
    else:
        print("Profile not saved.")

# ------------ MEMORY MEASURE ONCE -----------
def mem_measure_once():
    process = psutil.Process(os.getpid())
    memory_info = process.memory_info()

    # Convert RSS memory to MB
    memory_mb = memory_info.rss / (1024 * 1024)
    return round(memory_mb,2)

# ---------------- MEMORY MONITOR ----------------
def monitor_peak_memory(process, peak, stop_event, interval=0.02):
    try:
        while not stop_event.is_set():
            rss = process.memory_info().rss
            if rss > peak[0]:
                peak[0] = rss
            time.sleep(interval)
    except psutil.NoSuchProcess:
        pass


# ---------------- SINGLE HASH TEST ----------------
def hash_once(password, time_cost, memory_cost_kib, parallelism=1, hash_len=32, salt_len=16, return_hash=False):
    if time_cost <= 0 or memory_cost_kib <= 0:
        raise ValueError("time_cost and memory_cost_kib must be > 0")
    ensure_memory_safe(memory_cost_kib)
    parallelism = clamp_parallelism(parallelism)
    ph = PasswordHasher(
        time_cost=time_cost,
        memory_cost=memory_cost_kib,
        parallelism=parallelism,
        hash_len=hash_len,
        salt_len=salt_len,
        type=Type.ID,
    )

    process = psutil.Process(os.getpid())
    peak = [process.memory_info().rss]
    stop_event = Event()
    thread = Thread(target=monitor_peak_memory, args=(process, peak, stop_event), daemon=True)
    thread.start()

    start = time.perf_counter()
    try:
        generated_hash = ph.hash(password)
    finally:
        end = time.perf_counter()
        stop_event.set()
        thread.join()
    if return_hash:
        return end - start, peak[0], generated_hash
    return end - start, peak[0]


# ---------------- BENCHMARK ----------------
def benchmark_argon2id(password, profile):
    mem_overhead=mem_measure_once()
    print("\nSelected profile parameters:")
    print(f"  time_cost   : {profile['time_cost']}")
    print(f"  memory_cost : {profile['memory_cost_kib'] / 1024:.1f} MiB")
    print(f"  parallelism : {profile['parallelism']}")
    print(f"  hash length : {profile['hash_len']}")
    print(f"  salt length : {profile['salt_len']}")

    try:
        runs_input = type_validated_input("\nEnter number of benchmark runs [default 5]: ", int)
        runs = int(runs_input) if runs_input else 5
    except ValueError:
        print("Invalid number, using 5 runs")
        runs = 5

    print(f"\nRunning benchmark for {runs} runs...\n")
    timings = []
    peaks = []
    final_hash=None

    for i in range(runs):
        if i == runs - 1:
            elapsed, peak, final_hash = hash_once(
                password,
                profile['time_cost'],
                profile['memory_cost_kib'],
                profile['parallelism'],
                profile['hash_len'],
                profile['salt_len'],
                return_hash=True
            )
        else:
            elapsed, peak = hash_once(
                password,
                profile['time_cost'],
                profile['memory_cost_kib'],
                profile['parallelism'],
                profile['hash_len'],
                profile['salt_len']
            )
        timings.append(elapsed)
        peaks.append(peak)

        print(
            f"Run {i + 1}: "
            f"time = {elapsed:.4f}s | "
            f"peak memory = {peak / (1024 * 1024):.2f} MiB"
        )

    print("\nExample Argon2id hash using the dummy password and selected parameters:")
    print(final_hash)
    min_time = min(timings)
    max_time = max(timings)
    avg_time = sum(timings) / runs
    avg_peak = sum(peaks) / runs
    print("-" * 50)
    show_ms = min_time < 0.2

    if show_ms:
        print(f"Shortest time:       {min_time:.4f} s ({min_time * 1000:.2f} ms)")
        print(f"Longest time:        {max_time:.4f} s ({max_time * 1000:.2f} ms)")
        print(f"Average time:        {avg_time:.4f} s ({avg_time * 1000:.2f} ms)")
        print(f"Average peak memory: {avg_peak / (1024 * 1024):.2f} MiB")
        print(f"Script mem overhead: {mem_overhead} MiB")
        print(f"Real hash memory:    {avg_peak / (1024 * 1024) - mem_overhead} MiB")
    else:
        print(f"Shortest time:       {min_time:.4f} s")
        print(f"Longest time:        {max_time:.4f} s")
        print(f"Average time:        {avg_time:.4f} s")
        print(f"Average peak memory: {avg_peak / (1024 * 1024):.2f} MiB")
        print(f"Script mem overhead: {mem_overhead} MiB")


# ----------------AUTO-TUNE ----------------
class OscillationDetector:

    def __init__(self, threshold=OSCILLATION_THRESHOLD):
        self.history = []  # List of (elapsed, target) tuples
        self.threshold = threshold

    def add_result(self, elapsed, target):
        self.history.append((elapsed, target))

    def is_oscillating(self):
        if len(self.history) < self.threshold + 1:
            return False

        recent = self.history[-(self.threshold + 1):]
        direction_changes = 0
        for i in range(len(recent) - 1):
            prev_over = recent[i][0] > recent[i][1]
            curr_over = recent[i + 1][0] > recent[i + 1][1]
            if prev_over != curr_over:
                direction_changes += 1

        return direction_changes >= self.threshold


def damped_adjustment(value, ratio, is_memory=True, damping_factor=0.6):
    """
    More conservative adjustment when high ratio detected.
    Uses damping to prevent wild oscillations.
    """
    if is_memory:
        if ratio < 1.0:  # undershoot
            # Increase, but with damping
            if ratio < 0.7:
                factor = 1.10
            elif ratio < 0.85:
                factor = 1.05
            else:
                factor = 1.02
            return int(value * factor)
        else:  # overshoot
            # Decrease, but with damping to prevent undershooting
            if ratio > 2.0:
                # Cap the reduction - don't reduce by more than 40%
                factor = max(0.6, 1 / (ratio ** damping_factor))
            else:
                factor = COARSE_DOWN_FACTOR
            return max(MIN_MEM_STEP_KIB, int(value * factor))
    else:  # time_cost
        if ratio < 1.0:  # undershoot
            # Conservative increase
            return value + 1
        else:  # overshoot
            if ratio > 2.0:
                # Cap the decrement to at most 50% of current value
                max_decrement = max(1, value // 2)
                calculated_decrement = int(value * (1 - 1 / (ratio ** damping_factor)))
                decrement = min(max_decrement, calculated_decrement)
                return max(1, value - decrement)
            else:
                return max(1, value - 1)

def auto_tune(password, profiles):
    target_input = type_validated_input("\nEnter desired hash time in seconds [default 1.0]: ", float)
    try:
        target_time = target_input if target_input else 1.0
    except ValueError:
        print("Invalid target time")
        return
    if target_time <= 0:
        print("Target time must be > 0")
        return

    if type_validated_input("Set custom hash or salt length? (y/n): ", str, enforce_input=True).strip().lower() in {"y", "yes"}:
        try:
            hash_len_input = type_validated_input("Enter hash length [default 32]: ", int)
            salt_len_input = type_validated_input("Enter salt length [default 16]: ", int)

            hash_len = int(hash_len_input) if hash_len_input else 32
            salt_len = int(salt_len_input) if salt_len_input else 16

            if hash_len <= 0 or salt_len <= 0:
                print("hash_len and salt_len must be > 0")
                return

        except ValueError:
            print("Invalid hash/salt length")
            return
    else:
        hash_len = 32
        salt_len = 16

    fixed_choice = type_validated_input("Set which parameter as fixed? (time[t]/memory[m]): ", str, enforce_input=True).strip().lower()
    try:
        parallelism = clamp_parallelism(type_validated_input("Enter parallelism: ", int, enforce_input=True))
        if fixed_choice in ("time", "t"):
            time_cost = type_validated_input("Enter fixed time_cost: ", int, enforce_input=True)
            memory_cost_kib = type_validated_input("Enter starting memory cost [MiB]: ", int, enforce_input=True) * 1024
            adjust = "memory"
        elif fixed_choice in ("memory", "m"):
            memory_cost_kib = type_validated_input("Enter fixed memory_cost [MiB]: ", int) * 1024
            time_cost = type_validated_input("Enter starting time_cost: ", int)
            adjust = "time"
        else:
            print("Invalid choice")
            return
    except ValueError:
        print("Invalid numeric input")
        return

    # Pre-validate memory safety
    try:
        ensure_memory_safe(memory_cost_kib)
    except MemoryError as e:
        print(f"Initial memory configuration unsafe: {e}")
        return

    confirm = type_validated_input(f"\n_______________RECAP_______________\n"
                                   f"Target hash time: {target_time}s\n"
                                   f"Parallelism: {parallelism}\n"
                                   f"Time cost: {time_cost}\n"
                                   f"Memory cost: {memory_cost_kib/1024} MiB\n"
                                   f"Cost parameter to tune: {adjust}\n"
                                   f"Hash length: {hash_len}\n"
                                   f"Salt length: {salt_len}\n"
                                   f"___________________________________\n"
                                   f"Proceed with these values? [y/n]: ", str, enforce_input=True).strip().lower()
    if confirm == "n":
        print("Aborted.")
        return

    print(f"\nAuto-tuning to target {target_time:.2f}s (parallelism={parallelism})\n")

    oscillation_detector = OscillationDetector()
    last_under = None
    last_over = None
    damping_active = False

    # ---------- coarse tuning ----------
    for iteration in range(MAX_TUNE_ITER):
        try:
            elapsed, peak = hash_once(password, time_cost, memory_cost_kib, parallelism, hash_len, salt_len)
        except MemoryError as e:
            print(f"{e}")
            if adjust == "memory":
                print("Reducing memory and retrying...")
                memory_cost_kib = max(MIN_MEM_STEP_KIB, memory_cost_kib // 2)
                continue
            else:
                return

        ratio = elapsed / target_time
        oscillation_detector.add_result(elapsed, target_time)

        print(f"[Iter {iteration + 1}] time_cost={time_cost}, memory_cost={memory_cost_kib / 1024:.1f} MiB → "
              f"{elapsed:.3f}s | peak memory: {peak / (1024 * 1024):.1f} MiB | ratio: {ratio:.2f}")

        # Check for oscillation
        if oscillation_detector.is_oscillating() and not damping_active:
            print("⚠ Oscillation detected! Enabling damped adjustment...")
            damping_active = True

        # Record under/over
        if elapsed < target_time:
            if last_under is None or elapsed > last_under[2]:
                last_under = (time_cost, memory_cost_kib, elapsed, peak)
        else:
            if last_over is None or elapsed < last_over[2]:
                last_over = (time_cost, memory_cost_kib, elapsed, peak)

        # Check if bracketed
        if last_under and last_over:
            print(f"✓ Target bracketed after {iteration + 1} iterations")
            break

        # ---------- coarse adjustment ----------
        if adjust == "memory":
            if damping_active:
                memory_cost_kib = damped_adjustment(memory_cost_kib, ratio, is_memory=True)
            else:
                if elapsed < target_time:
                    factor = 1.20 if ratio < 0.8 else 1.15 if ratio < 0.9 else 1.05
                    memory_cost_kib = int(memory_cost_kib * factor)
                else:
                    if ratio > 1.5:
                        factor = max(0.6, 1 / (ratio * 0.8))
                        memory_cost_kib = max(MIN_MEM_STEP_KIB, int(memory_cost_kib * factor))
                        print(f"⚠ High ratio detected ({ratio:.2f}), reducing memory to {memory_cost_kib / 1024:.1f} MiB")
                    else:
                        memory_cost_kib = max(MIN_MEM_STEP_KIB, int(memory_cost_kib * COARSE_DOWN_FACTOR))

            try:
                ensure_memory_safe(memory_cost_kib)
            except MemoryError:
                print(f"⚠ Adjusted memory exceeds safe limit, capping...")
                memory_cost_kib = int(available_memory_kib() * MEMORY_SAFETY_RATIO)


        else:  # adjust == "time"

            # Always use damping helper if damping_active, else rough coarse adjustment

            if damping_active:
                time_cost = damped_adjustment(time_cost, ratio, is_memory=False)

            else:
                if elapsed < target_time:
                    # Undershoot → increase time_cost aggressively depending on ratio
                    if ratio < 0.8:
                        time_cost += max(1, int(time_cost * 0.25))
                    elif ratio < 0.9:
                        time_cost += max(1, int(time_cost * 0.10))
                    else:
                        time_cost += 1
                else:
                    # Overshoot → decrease time_cost aggressively if ratio high
                    if ratio > 1.5:
                        max_decrement = max(1, time_cost // 2)
                        calculated_decrement = int(
                            time_cost * (1 - 1 / (ratio ** 0.6)))  # same damping factor as helper
                        decrement = min(max_decrement, max(1, calculated_decrement))
                        time_cost = max(1, time_cost - decrement)
                        print(f"⚠ High ratio detected ({ratio:.2f}), reducing time_cost to {time_cost}")
                    else:
                        time_cost = max(1, time_cost - 1)

    if not last_under or not last_over:
        print("✖ Could not bracket target within iteration limit")
        return

    # ---------- fine-tuning phase ----------
    if adjust == "memory":
        print("\n" + "=" * 60)
        print("FINE-TUNING PHASE: Binary search for optimal parameters")
        print("=" * 60 + "\n")
        best_candidate = fine_tune_memory(password, last_under, last_over, target_time, parallelism, hash_len, salt_len)
    else:
        # Time tuning removed: pick closest under-target candidate
        best_candidate = last_under
        print(f"Selected time_cost candidate: time_cost={best_candidate[0]}, "
              f"memory_cost={best_candidate[1] / 1024:.1f} MiB → {best_candidate[2]:.3f}s")

    if best_candidate:
        final_elapsed, _, final_hash = hash_once(password,best_candidate[0], best_candidate[1],parallelism, hash_len, salt_len, return_hash=True)
        print("\n✔ Tuning complete")
        print("\nExample Argon2id hash using the dummy password and final parameters:")
        print(final_hash)
        print(f"\nFinal parameters:")
        print(f"  time_cost   = {best_candidate[0]}")
        print(f"  memory_cost = {best_candidate[1] / 1024:.1f} MiB")
        print(f"  parallelism = {parallelism}")
        print(f"  hash length = {hash_len}")
        print(f"  salt length = {salt_len}")
        if best_candidate[2] <0.2 or final_elapsed < 0.2:
            print(f"  hash time   ~ During tuning: {best_candidate[2]:.3f}s ({best_candidate[2] * 1000:.2f} ms), Final run: {final_elapsed:.3f}s ({final_elapsed * 1000:.2f} ms)")
        else:
            print(f"  hash time   ~ During tuning: {best_candidate[2]:.3f}s, Final run: {final_elapsed:.3f}s")
        prompt_save_profile(profiles, best_candidate[0], best_candidate[1], parallelism, hash_len, salt_len)

def fine_tune_memory(password, last_under, last_over, target_time, parallelism, hash_len, salt_len):
    """Fine-tune memory cost using binary search"""
    print("Fine-tuning memory (converging from below)...\n")

    best_candidate = last_under
    lower_bound = last_under[1]
    upper_bound = last_over[1]
    time_cost = last_under[0]

    for iteration in range(MAX_TUNE_ITER):
        mid_mem = lower_bound + (upper_bound - lower_bound) // 2

        # Check convergence
        if upper_bound - lower_bound <= MIN_MEM_STEP_KIB:
            print(f"Converged: bounds within {MIN_MEM_STEP_KIB} KiB, reverting to last known coarse-tuned parameters under target time.")
            break

        if mid_mem <= lower_bound or mid_mem >= upper_bound:
            break

        try:
            elapsed, peak = hash_once(password, time_cost, mid_mem, parallelism, hash_len, salt_len)
        except MemoryError as e:
            print(f"⚠ Memory test failed: {e}")
            upper_bound = mid_mem
            continue

        print(
            f"[Fine iter {iteration + 1}] time_cost={time_cost}, memory_cost={mid_mem / 1024:.1f} MiB → {elapsed:.3f}s")

        # Reject overshoot immediately
        if elapsed > target_time:
            upper_bound = mid_mem
            continue

        # Update best if this is better
        if elapsed > best_candidate[2]:
            best_candidate = (time_cost, mid_mem, elapsed, peak)

        # Check if within epsilon
        if elapsed >= target_time * (1 - TUNING_EPSILON):
            if verify_stability(password, best_candidate[0], best_candidate[1],
                                parallelism, target_time, hash_len, salt_len):
                print("✔ Stable configuration found")
                return best_candidate
            else:
                # If unstable, narrow the search
                if elapsed > target_time * (1 - TUNING_EPSILON / 2):
                    upper_bound = mid_mem
                else:
                    lower_bound = mid_mem
                continue

        # Update bounds
        if elapsed < target_time:
            lower_bound = mid_mem
        else:
            upper_bound = mid_mem

    return best_candidate


def verify_stability(password, time_cost, memory_cost_kib, parallelism, target_time, hash_len, salt_len, runs=5):
    """Verify that configuration produces stable results over multiple runs"""
    print(f"\n  Verifying stability over {runs} runs..."
          f"\n =================================================")
    run_times = []

    for i in range(runs):
        run_time, _ = hash_once(password, time_cost, memory_cost_kib, parallelism, hash_len, salt_len)
        run_times.append(run_time)
        within_target = target_time * (1 - TUNING_EPSILON) <= run_time < target_time
        status = "✓" if within_target else "✗"
        print(f"    Run {i + 1}: {run_time:.3f}s {status}")

    # Check if all runs are within acceptable range
    all_stable = all(
        target_time * (1 - TUNING_EPSILON) <= rt < target_time
        for rt in run_times
    )

    if all_stable:
        avg = sum(run_times) / len(run_times)
        print(f"  ✓ All runs stable (avg: {avg:.3f}s)")
        return True
    else:
        print(f"  ✗ Unstable: some runs outside target range")
        return False

# ---------------- MAIN LOOP ----------------
def main_loop():
    try:
        profiles = initialize_profiles()
        show_system_info()
        run_main = True

        while run_main:
            print("\nChoose mode:")
            print("  1 → Benchmark profile")
            print("  2 → Auto-tune hash time")
            print("  3 → Measure current script memory usage")
            print("  Q → Exit")
            mode = type_validated_input("> ", str, enforce_input=True).strip()

            if mode == "1":
                profile_num, profile = select_profile(profiles)
                if profile:
                    benchmark_argon2id(DUMMY_PASSWORD, profile)
                type_validated_input("\nPress Enter to return to main menu...", str)

            elif mode == "2":
                auto_tune(DUMMY_PASSWORD, profiles)
                type_validated_input("\nPress Enter to return to main menu...", str)

            elif mode == "3":
                print(f"Memory used: {mem_measure_once()} MB")

            elif mode in {"q", "Q"}:
                print("Exiting application")
                run_main = False

            else:
                print("Invalid selection. Try again.")
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")


# ---------------- RUN ----------------
if __name__ == "__main__":
    main_loop()