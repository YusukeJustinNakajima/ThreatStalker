import subprocess

def run_hayabusa_command(evtx_flag=None, evtx_file=None):
    """Execute the hayabusa command with an optional evtx file parameter."""
    cmd = ["hayabusa", "csv-timeline", "--no-wizard", "--quiet", "--rules", "chainrule"]
    if evtx_flag and evtx_file:
        cmd.extend([evtx_flag, evtx_file])
    try:
        print("\n\nExecuting hayabusa...\n\n")
        subprocess.run(cmd, check=True)
    except Exception as e:
        print(f"Error running hayabusa command: {e}")
