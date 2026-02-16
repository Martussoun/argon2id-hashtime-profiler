import time
import psutil
import os
import json
from threading import Thread, Event
from argon2 import PasswordHasher
from argon2.low_level import Type

# ---------------- CONSTANTS ----------------
PROFILES_FILE = "argon2_profiles.json"
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
    "parallelism": 1
}

# Oscillation detection
OSCILLATION_THRESHOLD = 3  # Number of direction changes before triggering damping


# ---------------- HELPERS ----------------
def clamp_parallelism(p):
    max_p = psutil.cpu_count(logical=True) or 1
    return max(1, min(p, max_p))


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
        f"  Recommended maximum memory cost: {recommended_max_mib:.1f} MiB (~{int(MEMORY_SAFETY_RATIO * 100)}% of available RAM)")


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
    choice = input("Select profile by number (Enter for default): ").strip()
    if not choice:
        choice = str(DEFAULT_PROFILE_NUMBER)
    if choice in profiles:
        return choice, profiles[choice]["params"]
    print("Invalid selection")
    return None, None


def prompt_save_profile(profiles, time_cost, memory_cost_kib, parallelism):
    choice = input("Save profile? (y/n): ").strip().lower()
    if choice == "y":
        if len(profiles) < MAX_PROFILES:
            profile_name = input("Enter profile name to save: ").strip()
            if not profile_name:
                print("No name entered. Skipping save.")
                return
        else:
            print("\n⚠ Maximum profiles reached. Choose one to overwrite:")
            list_profiles(profiles)
            sel = input("Enter number of profile to overwrite: ").strip()
            if sel not in profiles or sel == str(DEFAULT_PROFILE_NUMBER):
                print("Invalid selection or cannot overwrite default. Skipping save.")
                return
            profile_name = input("Enter new profile name: ").strip()
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
                "parallelism": parallelism
            }
        }
        save_profiles(profiles)
    else:
        print("Profile not saved.")


# ---------------- MEMORY MONITOR ----------------
def monitor_peak_memory(process, peak, stop_event, interval=0.005):
    try:
        while not stop_event.is_set():
            rss = process.memory_info().rss
            if rss > peak[0]:
                peak[0] = rss
            time.sleep(interval)
    except psutil.NoSuchProcess:
        pass


# ---------------- SINGLE HASH TEST ----------------
def hash_once(password, time_cost, memory_cost_kib, parallelism=1, hash_len=32, salt_len=16):
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
        ph.hash(password)
    finally:
        end = time.perf_counter()
        stop_event.set()
        thread.join()
    return end - start, peak[0]


# ---------------- BENCHMARK ----------------
def benchmark_argon2id(password, profile):
    print("\nSelected profile parameters:")
    print(f"  time_cost   : {profile['time_cost']}")
    print(f"  memory_cost : {profile['memory_cost_kib'] / 1024:.1f} MiB")
    print(f"  parallelism : {profile['parallelism']}")

    try:
        runs_input = input("\nEnter number of benchmark runs [default 5]: ").strip()
        runs = int(runs_input) if runs_input else 5
    except ValueError:
        print("Invalid number, using 5 runs")
        runs = 5

    print(f"\nRunning benchmark for {runs} runs...\n")
    timings = []
    peaks = []

    for i in range(runs):
        elapsed, peak = hash_once(
            password,
            profile['time_cost'],
            profile['memory_cost_kib'],
            profile['parallelism']
        )
        timings.append(elapsed)
        peaks.append(peak)
        print(
            f"Run {i + 1}: "
            f"time = {elapsed:.4f}s | "
            f"peak memory = {peak / (1024 * 1024):.2f} MiB"
        )

    avg_time = sum(timings) / runs
    avg_peak = sum(peaks) / runs
    print("-" * 50)
    print(f"Average time:        {avg_time:.4f} s")
    print(f"Average peak memory: {avg_peak / (1024 * 1024):.2f} MiB")


# ---------------- IMPROVED AUTO-TUNE ----------------
class OscillationDetector:
    """Detects when tuning is oscillating between over/under target"""

    def __init__(self, threshold=OSCILLATION_THRESHOLD):
        self.history = []  # List of (elapsed, target) tuples
        self.threshold = threshold

    def add_result(self, elapsed, target):
        self.history.append((elapsed, target))

    def is_oscillating(self):
        if len(self.history) < self.threshold + 1:
            return False

        # Check if we're alternating between over and under
        direction_changes = 0
        for i in range(len(self.history) - 1):
            prev_over = self.history[i][0] > self.history[i][1]
            curr_over = self.history[i + 1][0] > self.history[i + 1][1]
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
    target_input = input("\nEnter desired hash time in seconds [default 1.0]: ").strip()
    try:
        target_time = float(target_input) if target_input else 1.0
    except ValueError:
        print("Invalid target time")
        return
    if target_time <= 0:
        print("Target time must be > 0")
        return

    fixed_choice = input("Set which parameter as fixed? (time[t]/memory[m]): ").strip().lower()
    try:
        parallelism = clamp_parallelism(int(input("Enter parallelism: ")))
        if fixed_choice in ("time", "t"):
            time_cost = int(input("Enter fixed time_cost: "))
            memory_cost_kib = int(input("Enter starting memory cost [MiB]: ")) * 1024
            adjust = "memory"
        elif fixed_choice in ("memory", "m"):
            memory_cost_kib = int(input("Enter fixed memory_cost [MiB]: ")) * 1024
            time_cost = int(input("Enter starting time_cost: "))
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
        print(f"🛑 Initial memory configuration unsafe: {e}")
        return

    confirm = input("Proceed with these values? [Y/n]: ").strip().lower()
    if confirm == "n":
        print("Aborted. Returning to main menu.")
        return

    print(f"\nAuto-tuning to target {target_time:.2f}s (parallelism={parallelism})\n")

    oscillation_detector = OscillationDetector()
    last_under = None
    last_over = None
    damping_active = False

    # ---------- coarse tuning ----------
    for iteration in range(MAX_TUNE_ITER):
        try:
            elapsed, peak = hash_once(password, time_cost, memory_cost_kib, parallelism)
        except MemoryError as e:
            print(f"🛑 {e}")
            if adjust == "memory":
                print("Reducing memory and retrying...")
                memory_cost_kib = max(MIN_MEM_STEP_KIB, memory_cost_kib // 2)
                continue
            else:
                return

        ratio = elapsed / target_time
        oscillation_detector.add_result(elapsed, target_time)

        print(
            f"[Iter {iteration + 1}] time_cost={time_cost}, memory_cost={memory_cost_kib / 1024:.1f} MiB → "
            f"{elapsed:.3f}s | peak memory: {peak / (1024 * 1024):.1f} MiB | ratio: {ratio:.2f}"
        )

        # Check for oscillation
        if oscillation_detector.is_oscillating() and not damping_active:
            print("⚠ Oscillation detected! Enabling damped adjustment...")
            damping_active = True

        # Record under/over
        if elapsed < target_time:
            last_under = (time_cost, memory_cost_kib, elapsed, peak)
        else:
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
                    # undershoot → increase memory
                    factor = 1.20 if ratio < 0.8 else 1.15 if ratio < 0.9 else 1.05
                    memory_cost_kib = int(memory_cost_kib * factor)
                else:
                    # overshoot → reduce memory (with improved handling)
                    if ratio > 1.5:
                        # More conservative reduction to avoid wild swings
                        factor = max(0.6, 1 / (ratio * 0.8))  # Damped by 0.8
                        memory_cost_kib = max(MIN_MEM_STEP_KIB, int(memory_cost_kib * factor))
                        print(
                            f"⚠ High ratio detected ({ratio:.2f}), reducing memory to {memory_cost_kib / 1024:.1f} MiB")
                    else:
                        memory_cost_kib = max(MIN_MEM_STEP_KIB, int(memory_cost_kib * COARSE_DOWN_FACTOR))

            # Validate memory safety before next iteration
            try:
                ensure_memory_safe(memory_cost_kib)
            except MemoryError as e:
                print(f"⚠ Adjusted memory exceeds safe limit, capping...")
                memory_cost_kib = int(available_memory_kib() * MEMORY_SAFETY_RATIO)

        else:  # adjust == "time"
            if damping_active:
                time_cost = damped_adjustment(time_cost, ratio, is_memory=False)
            else:
                if elapsed < target_time:
                    # undershoot → increase time_cost
                    time_cost += 1
                else:
                    # overshoot → reduce time_cost (with improved handling)
                    if ratio > 1.5:
                        # More conservative reduction
                        max_decrement = max(1, time_cost // 2)  # Cap at 50%
                        calculated_decrement = int(time_cost * (1 - 1 / (ratio * 0.9)))
                        decrement = min(max_decrement, max(1, calculated_decrement))
                        time_cost = max(1, time_cost - decrement)
                        print(f"⚠ High ratio detected ({ratio:.2f}), reducing time_cost to {time_cost}")
                    else:
                        time_cost = max(1, time_cost - 1)

    if not last_under or not last_over:
        print("✖ Could not bracket target within iteration limit")
        return

    # ---------- fine-tuning phase ----------
    print("\n" + "=" * 60)
    print("FINE-TUNING PHASE: Binary search for optimal parameters")
    print("=" * 60 + "\n")

    if adjust == "memory":
        best_candidate = fine_tune_memory(
            password, last_under, last_over, target_time, parallelism
        )
    else:
        best_candidate = fine_tune_time_cost(
            password, last_under, last_over, target_time, parallelism
        )

    if best_candidate:
        print("\n✔ Tuning complete")
        print(f"Final parameters:")
        print(f"  time_cost   = {best_candidate[0]}")
        print(f"  memory_cost = {best_candidate[1] / 1024:.1f} MiB")
        print(f"  parallelism = {parallelism}")
        print(f"  hash time   = {best_candidate[2]:.3f}s")
        prompt_save_profile(profiles, best_candidate[0], best_candidate[1], parallelism)


def fine_tune_memory(password, last_under, last_over, target_time, parallelism):
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
            print(f"✓ Converged: bounds within {MIN_MEM_STEP_KIB} KiB")
            break

        if mid_mem <= lower_bound or mid_mem >= upper_bound:
            break

        try:
            elapsed, peak = hash_once(password, time_cost, mid_mem, parallelism)
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
                                parallelism, target_time):
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


def fine_tune_time_cost(password, last_under, last_over, target_time, parallelism):
    """Fine-tune time_cost using binary search"""
    print("Fine-tuning time_cost (converging from below)...\n")

    best_candidate = last_under
    lower_bound = last_under[0]
    upper_bound = last_over[0]
    memory_cost_kib = last_under[1]

    for iteration in range(MAX_TUNE_ITER):
        mid_time = lower_bound + (upper_bound - lower_bound) // 2

        # Check convergence - FIXED: was <= 0, now <= 1
        if upper_bound - lower_bound <= 1:
            print(f"✓ Converged: bounds within 1 time_cost unit")
            break

        if mid_time <= lower_bound or mid_time >= upper_bound:
            break

        elapsed, peak = hash_once(password, mid_time, memory_cost_kib, parallelism)
        print(
            f"[Fine iter {iteration + 1}] time_cost={mid_time}, memory_cost={memory_cost_kib / 1024:.1f} MiB → {elapsed:.3f}s")

        # Reject overshoot immediately
        if elapsed > target_time:
            upper_bound = mid_time
            continue

        # Update best if this is better
        if elapsed > best_candidate[2]:
            best_candidate = (mid_time, memory_cost_kib, elapsed, peak)

        # Check if within epsilon
        if elapsed >= target_time * (1 - TUNING_EPSILON):
            if verify_stability(password, best_candidate[0], best_candidate[1],
                                parallelism, target_time):
                print("✔ Stable configuration found")
                return best_candidate
            else:
                # If unstable, narrow the search
                if elapsed > target_time * (1 - TUNING_EPSILON / 2):
                    upper_bound = mid_time
                else:
                    lower_bound = mid_time
                continue

        # Update bounds
        if elapsed < target_time:
            lower_bound = mid_time
        else:
            upper_bound = mid_time

    return best_candidate


def verify_stability(password, time_cost, memory_cost_kib, parallelism, target_time, runs=5):
    """Verify that configuration produces stable results over multiple runs"""
    print(f"\n  Verifying stability over {runs} runs...")
    run_times = []

    for i in range(runs):
        run_time, _ = hash_once(password, time_cost, memory_cost_kib, parallelism)
        run_times.append(run_time)
        within_target = target_time * (1 - TUNING_EPSILON) <= run_time <= target_time
        status = "✓" if within_target else "✗"
        print(f"    Run {i + 1}: {run_time:.3f}s {status}")

    # Check if all runs are within acceptable range
    all_stable = all(
        target_time * (1 - TUNING_EPSILON) <= rt <= target_time
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
    PASSWORD = "samp1ep@ssw0rD:_165"
    profiles = initialize_profiles()
    show_system_info()
    run_main = True

    while run_main:
        print("\nChoose mode:")
        print("  1 → Benchmark profile")
        print("  2 → Auto-tune hash time")
        print("  3 → Exit")
        mode = input("> ").strip()

        if mode == "1":
            profile_num, profile = select_profile(profiles)
            if profile:
                benchmark_argon2id(PASSWORD, profile)
            input("\nPress Enter to return to main menu...")
        elif mode == "2":
            auto_tune(PASSWORD, profiles)
            input("\nPress Enter to return to main menu...")
        elif mode == "3":
            print("Exiting application. Goodbye!")
            run_main = False
        else:
            print("Invalid selection. Try again.")


# ---------------- RUN ----------------
if __name__ == "__main__":
    main_loop()