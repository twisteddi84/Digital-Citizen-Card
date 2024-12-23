# Digital-Citizen-Card
This project implements a system for selectively disclosing identity attributes in a digital environment while proving their ownership and ensuring their correctness. Inspired by traditional Citizen Cards (CC), the system allows users to generate a Digital Citizen Card (DCC), selectively disclose attributes, and validate them securely.

## How to run
### Start the issuer server

```bash
cd issuer 
```

```bash
python3 gen_dcc.py
```

### Generate request
```bash
cd owner
```

```bash
python3 req_dcc.py
```
Follow menu steps and use the card reader. This file will save a JSON file named dcc_final.json by default.


### Generate the Min DCC
```bash
cd owner 
```

```bash
python3 gen_min_dcc.py
```

Follow steps indicated in the script. This script will create a min_dcc.json file by default

### Check the Min Dcc
```bash
cd owner 
```

```bash
python3 check_dcc.py
```

Follow the menu.