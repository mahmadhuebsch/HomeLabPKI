import subprocess
import sys
from pathlib import Path
import pytest


@pytest.mark.unit
@pytest.mark.integration
def test_black_formatting():
    """
    Run black --check on the project root to ensure code formatting compliance.
    """
    # Get the project root directory (assuming this test is in tests/)
    project_root = Path(__file__).resolve().parent.parent

    # Run black in check mode
    # We use sys.executable to ensure we use the same python environment
    cmd = [sys.executable, "-m", "black", "--check", str(project_root)]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        if result.returncode != 0:
            # If black finds files to format, it returns 1
            # If there is an internal error, it might return something else
            pytest.fail(f"Black formatting check failed. Run 'black .' to fix.\nOutput:\n{result.stderr}")

    except Exception as e:
        pytest.fail(f"Failed to run black: {str(e)}")
