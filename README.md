# Argon2 Hash Tuner & Benchmark Tool

An simple Python CLI utility for benchmarking and auto-tuning **Argon2id** hash parameters based on desired hash time.

## Features

-   **Memory Safety:** Monitors RSS memory usage and enforces a safety ratio (85% of available RAM) to prevent Out-Of-Memory (OOM) crashes
-   **Auto-Tuning:** Automatically adjusts hash parameters(time_cost or memory_cost) to hit a target execution time using bracketing search
-   **Profile Management:** Option to save configurations to a JSON file (`argon2_profiles.json`), the file is created on first run and contains a default config
-   **System Monitoring:** Provides real-time peak memory reporting alongside timing benchmarks

## Prerequisites

-   **Python 3.8+**
-   **POSIX System** (Unix/Linux/macOS) for accurate `psutil` memory reporting.

## Installation

1.  **Clone the repository**
    ```bash
    git clone https://github.com/Martussoun/argon2id-hashtime-profiler 
    ```
    **or download only `argon2id_hashtime_profiler.py`**
    ```bash
    curl -L -o argon2id_hashtime_profiler.py https://raw.githubusercontent.com/Martussoun/argon2id-hashtime-profiler/master/argon2id_hashtime_profiler.py
    ```
3.  **Create a virtual environment**
    ```bash
    python3 -m venv argonvenv
    ```
4. **Activate the virtual environment**
   (ubuntu example)
   ```bash
   source argonvenv/bin/activate
   ```
5.  **Install Python dependencies.** Run the following command in the terminal:
    ```bash
    pip install -r requirements.txt
    ```
    *(If you didnt download the `requirements.txt` file, install the following libs manually: `argon2-cffi` and `psutil`)*
    ```bash
    pip install argon2-cffi psutil
    ```

## Usage

Run the script directly:

```bash
python3 argon2id_hashtime_profiler.py
```

**(1) Benchmark Profile**

Executes a test hash using parameters from the selected JSON profile.
You can enter a custom number of runs (default: 5).
Displays average time and peak memory usage per run.
Shows a generated example hash.

**(2)Auto-tune Hash Time**

Runs an automated algorithm to find the best parameters to match a target hash time (e.g., 1.0s).
Enter desired parameters and select either time_cost or memory_cost to be set as fixed, then enter a starting point for the tuned parameter.
After the tuning finishes you will be offered an option to save the profile.

**(3)Exit**
Safely closes the application.

## NOTE:
 **The script uses a dummy password(sAMp1ep@ssw0rD:_T35t) for demonstration. Never use this password in a production environment and DO NOT use this script to hash real passwords(by changing the dummy password in the script) as they are displayed on benchmark/tuning completion!**

**This project is licensed under the MIT License - see the `LICENSE` file for details.**
