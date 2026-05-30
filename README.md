# ReconPilot

ReconPilot is a CLI tool for basic host and web reconnaissance.

## Install on Kali

```bash
git clone https://github.com/Heca898/ReconPilot.git
cd ReconPilot

sudo apt update
sudo apt install -y pipx
pipx ensurepath

pipx install .
reconpilot --help
```

## Usage

```bash
reconpilot <target>
```

Examples:

```bash
reconpilot 10.10.10.10
reconpilot 10.10.10.10 --mode recon
reconpilot 10.10.10.10 --mode version-detect
reconpilot https://example.com --mode web-basic
reconpilot 10.10.10.10 --output reports/target.md
reconpilot 10.10.10.10 --save-session --session-output sessions/run.json
```

Available modes:

- `recon`
- `web-basic`
- `version-detect`

Help:

```bash
reconpilot --help
python -m reconpilot --help
python main.py --help
```
