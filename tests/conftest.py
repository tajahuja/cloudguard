from pathlib import Path
import tempfile

# Tool-sandbox temporary folders can be inaccessible on Windows. Keep scratch local.
TEMP = Path(__file__).resolve().parents[1] / '.test-work'
TEMP.mkdir(exist_ok=True)
tempfile.tempdir = str(TEMP)
