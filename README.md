# 📦 pkg-verify

A Python CLI tool to check security vulnerabilities in **packages** from different ecosystems, querying **both**:

- **NVD** (National Vulnerability Database - NIST)
- **GHSA** (GitHub Security Advisory)

The tool searches by package name and optionally by version, merging results from both sources without unnecessary duplicates.

---

## 🚀 Features

- Queries **NVD** and **GHSA** automatically for each package.
- Supports multiple ecosystems (`npm`, `pip`, etc.).
- Optional version filtering (`-v` / `--version`).
- Colorful **table output** with [Rich](https://github.com/Textualize/rich).
- Export results to **JSON** and **XLSX**.
- Merges CVE and GHSA data when both are available.
- Configurable via `config.yaml` (API keys).
- Clean, object-oriented design for maintainability.

---

## 📦 Installation

Clone this repository and install dependencies:

```bash
git clone https://github.com/your-user/pkg-verify.git
cd pkg-verify
pip install -r requirements.txt
```
Main dependencies:

- `requests`
- `PyYAML`
- `rich`
- `openpyxl`

### 🔑 Configuration
Create a `config.yaml` file in the project root with your API keys:

```yaml
nvd_api_key: "YOUR_NVD_KEY"
github_token: "YOUR_GITHUB_PAT"
```

- **NVD API Key**: Get one for free at [NVD API Key Request](https://nvd.nist.gov/developers/request-api-key).
- **GitHub Token**: Generate at [GitHub Personal Access Tokens](https://github.com/settings/tokens) with minimal `public_repo` scope (only to increase request limits).

If you want to use a custom config file name:

```bash
python pkg-verify.py package -pm npm --config my_config.yaml
```

### 💻 Usage

Basic syntax:

```bash
python pkg-verify.py <package-name> [options]
```

Parameters:

| Flag         | Description                      | Example               |
|--------------|----------------------------------|-----------------------|
| `-pm`, `--pkg-mng` | Ecosystem (`npm`, `pip`, etc.)   | `-pm npm`             |
| `-v`, `--version`  | Specific package version         | `-v 1.2.3`            |
| `--config`   | Path to YAML configuration file  | `--config my_config.yaml` |

### 📂 Examples

1. Search by package name only:

```bash
python pkg-verify.py lodash
```

2. Search in the NPM ecosystem:

```bash
python pkg-verify.py lodash -pm npm
```

3. Search with a specific version:

```bash
python pkg-verify.py lodash -pm npm -v 4.17.15
```

4. Use a custom configuration file:

```bash
python pkg-verify.py lodash -pm npm --config creds.yaml
```

### 📊 Output

Results are displayed as a colorful table in your terminal:

```yaml
  Source │ CVE            │ GHSA                │ Sev.     │ Published              │ Affects Version? │ Affected Range      │ First Fixed       │ Summary
 ════════╪════════════════╪═════════════════════╪══════════╪════════════════════════╪══════════════════╪═════════════════════╪═══════════════════╪═════════════════════════════════════════════
  NVD    │ CVE-2020-8203  │                     │ HIGH     │ 2020-07-15T17:15:11.797│ YES              │ < 4.17.20           │ —                 │ Prototype pollution attack when using...
  GitHub │ CVE-2020-8203  │ GHSA-p6mc-m468-83gw │ HIGH     │ 2020-07-15T19:15:48Z   │ YES              │ >= 3.7.0, < 4.17.19 │ 4.17.19           │ Prototype Pollution in lodash
```

### 📤 Export

The script automatically saves results to:

- `output.json` — JSON format
- `output.xlsx` — Excel format

### 🛠 Internal Structure

The code follows Clean Code and OOP principles, structured into:

- `ConfigLoader` → Loads configuration from YAML.
- `NVDClient` → Queries NVD API.
- `GHSAClient` → Queries GHSA API.
- `VulnerabilityMerger` → Merges results without duplicates.
- `OutputFormatter` → Displays Rich tables and exports JSON/XLSX.
- `PkgVerify` → Main orchestrator.

### ⚠ Limits & Notes

- NVD and GitHub have rate limits per minute/hour, which are increased with API key/token.
- Versions outside the affected range will be marked as not affected.
- Detection depends on data availability from official APIs.

### 📜 License

MIT License — see the `LICENSE` file for details.

---

