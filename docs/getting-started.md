# Getting Started with FormalGuard

## Prerequisites

### Formal Verification Tool (one of):
- **SymbiYosys** (recommended for open-source users): [Install guide](https://symbiyosys.readthedocs.io/en/latest/install.html)
- **Synopsys VC Formal**: Commercial license required
- **Cadence JasperGold**: Commercial license required
- **Siemens OneSpin 360**: Commercial license required

### Python (for compliance tooling):
- Python 3.9+
- Install dependencies: `pip install -r requirements.txt`

## Installation

```bash
git clone https://github.com/formalguard/formalguard.git
cd formalguard
pip install -r requirements.txt
```

## First Verification Run

### 1. Verify the AES-256 Reference Design

```bash
cd reference_designs/aes256_core
make verify
```

This runs SymbiYosys with the `aes256_core.sby` configuration. All 9 AES-256 properties should prove successfully.

### 2. See Properties Catch a Bug

```bash
cd reference_designs/vuln_aes
make verify
```

The vulnerable design has a timing side-channel. You'll see timing properties fail with counterexamples while functional properties still pass.

### 3. Generate a Compliance Report

```bash
python tools/compliance_report.py --standard pci-dss --dry-run
```

This shows a text summary of PCI-DSS coverage. For a full HTML report:

```bash
python tools/compliance_report.py \
  --standard pci-dss \
  --results examples/compliance_audit/sample_results.json \
  --output reports/pci_dss.html
```

## Integrating with Your Own Design

### Step 1: Choose Properties

Browse the [Property Catalog](property-catalog.md) to find properties relevant to your design.

### Step 2: Write a Binding Module

FormalGuard properties connect through standardized interfaces. Create a binding module that maps your design's signals:

```systemverilog
module fg_bind_my_design;
  fg_aes256_if fg_aes();

  assign fg_aes.clk       = my_aes.clk;
  assign fg_aes.rst_n     = my_aes.reset_n;
  assign fg_aes.start     = my_aes.go;
  assign fg_aes.done      = my_aes.finished;
  // ... map all signals

  fg_aes_functional u_func (.aes(fg_aes.props));
  fg_aes_timing     u_time (.aes(fg_aes.props));
endmodule
```

### Step 3: Configure Your Tool

For SymbiYosys, create a `.sby` file listing your source files and the FormalGuard files. See `reference_designs/aes256_core/aes256_core.sby` as a template.

### Step 4: Run and Iterate

Run verification, fix any failures, and generate compliance reports.

## Tool-Specific Guides

### SymbiYosys
- FormalGuard properties work with SymbiYosys out of the box
- Recommended: `prove` mode with `smtbmc z3` engine
- Typical depth: 50-100 cycles

### VC Formal (Synopsys)
- Load FormalGuard property files as assertion modules
- Use `bind` statements to attach to your design hierarchy
- Configure formal analysis mode with appropriate reset sequence

### JasperGold (Cadence)
- Import FormalGuard SVA files as checker modules
- Use the `Prove` app for unbounded verification
- JasperGold's `Visualize` is helpful for debugging counterexamples
