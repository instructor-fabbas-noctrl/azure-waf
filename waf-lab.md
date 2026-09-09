# Azure Web Application Firewall — Two-Day Hands-On Lab Guide

**Format:** 2 days × 8 hours · Instructor-led working session
**Primary platform:** Web Application Firewall on Application Gateway (**WAF_v2**)
**Secondary platform:** WAF on Azure Front Door (Premium) — covered as an alternative
**Backend test app:** OWASP Juice Shop (private VM, no public IP)
**Managed rule set:** DRS 2.2 (OWASP CRS 3.3.4 + Microsoft Threat Intelligence)
**AI investigation:** Azure WAF plugin in Microsoft Security Copilot

Every hands-on step is given **two ways**: the **Portal** path (click-through, good for teaching and for customers who live in the portal) and the **CLI** path (`az` commands, repeatable, good for redeploys and IaC discussions). Run whichever fits the room; the CLI path is authoritative for teardown and re-runs.

---

## Table of contents

- [How to use this guide](#how-to-use-this-guide)
- [Two-day agenda at a glance](#two-day-agenda-at-a-glance)
- [Prerequisites and pre-flight checklist](#prerequisites)
- [Naming, variables, and conventions](#conventions)
- [Reference architecture](#architecture)
- **Day 1**
  - [Lab 1 — Build the network and backend](#lab1)
  - [Lab 2 — Deploy Application Gateway WAF_v2 in Detection mode](#lab2)
  - [Lab 3 — Wire diagnostics to Log Analytics](#lab3)
- **Day 2**
  - [Lab 4 — Attack testing and reading the logs](#lab4)
  - [Lab 5 — Tuning: exclusions and false positives](#lab5)
  - [Lab 6 — Custom rules (rate-limit, geo, IP, header)](#lab6)
  - [Lab 7 — Enforce Prevention and re-test](#lab7)
  - [Lab 8 — Security Copilot for WAF](#lab8)
  - [Lab 9 — Governance, alerting, and workbooks](#lab9)
- [Use cases (mapped to the labs)](#use-cases)
- [Cost model](#cost)
- [Troubleshooting playbook](#troubleshooting)
- [Teardown](#teardown)
- [Appendix A — Front Door WAF alternative](#appendix-a)
- [Appendix B — KQL query pack](#appendix-b)
- [Appendix C — Full deploy script (copy-paste)](#appendix-c)

---

<a name="how-to-use-this-guide"></a>
## How to use this guide

- **Presenter sandbox first.** Build the whole thing yourself once before the customer session. Everything here is written so you can stand it up in ~45 minutes end-to-end via the CLI script in Appendix C.
- **In the room**, drive the Portal path on screen for the concept-building labs (1, 2, 4, 8) and offer the CLI path for anyone who wants to follow in their own subscription.
- **One resource group** holds everything (`rg-waf-lab`). Teardown is a single command. Delete it at the end of each day if you are cost-sensitive, and rebuild from Appendix C the next morning (~10 min).
- **Detection before Prevention, always.** Labs 2–6 run in Detection mode so nothing is blocked while you learn. Lab 7 is the deliberate flip to Prevention.

---

<a name="two-day-agenda-at-a-glance"></a>
## Two-day agenda at a glance

### Day 1 — Foundations, build, and observability

| Time | Block | Type |
|---|---|---|
| 0:00–0:30 | Welcome, objectives, threat landscape (OWASP Top 10) | Lecture |
| 0:30–1:15 | WAF concepts: platforms, SKUs, rule sets, modes, anomaly scoring | Lecture |
| 1:15–1:30 | Break | — |
| 1:30–2:45 | **Lab 1** — Network + backend (Juice Shop) | Hands-on |
| 2:45–3:00 | Break | — |
| 3:00–4:30 | **Lab 2** — Deploy App Gateway WAF_v2 (Detection) | Hands-on |
| 4:30–5:15 | Lunch | — |
| 5:15–6:30 | **Lab 3** — Diagnostics → Log Analytics + first log read | Hands-on |
| 6:30–7:15 | Architecture patterns, layering DDoS, where WAF sits | Lecture |
| 7:15–8:00 | Day 1 recap, Q&A, homework prompts | Discussion |

### Day 2 — Attack, tune, enforce, and operate

| Time | Block | Type |
|---|---|---|
| 0:00–0:20 | Recap + rebuild check | Lecture |
| 0:20–1:30 | **Lab 4** — Attack testing (SQLi/XSS/path traversal) + logs | Hands-on |
| 1:30–1:45 | Break | — |
| 1:45–2:45 | **Lab 5** — Tuning, exclusions, false positives | Hands-on |
| 2:45–4:00 | **Lab 6** — Custom rules (rate-limit, geo, IP, header) | Hands-on |
| 4:00–4:45 | Lunch | — |
| 4:45–5:30 | **Lab 7** — Flip to Prevention, re-test | Hands-on |
| 5:30–6:45 | **Lab 8** — Security Copilot for WAF | Hands-on |
| 6:45–7:30 | **Lab 9** — Governance (Azure Policy), alerts, workbook | Hands-on |
| 7:30–8:00 | Cost review, teardown, wrap-up, next steps | Discussion |

---

<a name="prerequisites"></a>
## Prerequisites and pre-flight checklist

**Access and identity**
- An Azure subscription where you are **Owner** or **Contributor + User Access Administrator** on the resource group.
- For Lab 8: **Security Copilot** provisioned in the tenant and at least **Copilot contributor** role. (An M365 E5/E7 tenant may already have an inclusion SCU pool — check before provisioning standalone SCUs.)
- Quota for at least 1 small VM and 1 public IP in your chosen region.

**Tools**
- Azure CLI ≥ 2.60 (`az version`), or use **Azure Cloud Shell** (browser, nothing to install).
- `curl` (built into Cloud Shell, macOS, Linux, and modern Windows).
- A modern browser for the portal.

**Decisions to lock before you start**
- **Region** — pick one close to attendees; keep everything in one region. This guide uses `eastus`.
- **Rule set** — DRS 2.2 (default for new deployments).
- **Backend** — OWASP Juice Shop in Docker (this guide) or your own test site.

**Pre-flight (run once):**
```bash
az login
az account show --output table
az account set --subscription "<your-subscription-id>"
az provider register --namespace Microsoft.Network --wait
az provider register --namespace Microsoft.OperationalInsights --wait
az version
```

---

<a name="conventions"></a>
## Naming, variables, and conventions

Set these once per shell session (CLI path). The Portal path uses the same names.

```bash
# ---- Core variables (edit REGION if needed) ----
export RG="rg-waf-lab"
export LOC="eastus"
export VNET="vnet-waf-lab"
export SNET_AGW="snet-appgw"       # dedicated App Gateway subnet
export SNET_BE="snet-backend"      # backend VM subnet
export PIP="pip-waf-lab"           # public IP for the gateway
export AGW="agw-waf-lab"           # Application Gateway
export WAFPOL="wafpol-waf-lab"     # WAF policy
export VM="vm-juice"               # backend VM
export LAW="law-waf-lab"           # Log Analytics workspace
export ADMIN="azureuser"
```

| Convention | Value |
|---|---|
| Resource group | `rg-waf-lab` (everything lives here; delete to tear down) |
| VNet / subnets | `vnet-waf-lab` → `snet-appgw` (10.0.1.0/24), `snet-backend` (10.0.2.0/24) |
| Gateway SKU | `WAF_v2`, autoscale min 0 / max 2 for the lab |
| Rule set | `OWASP 3.2` engine label in CLI maps to DRS; we set **DRS 2.2** in the policy |
| Mode | **Detection** for Labs 2–6, **Prevention** in Lab 7 |
| Backend | Private VM, Juice Shop on port 3000, **no public IP** |

> **Why the backend has no public IP:** it forces every request through the gateway. If the VM were publicly reachable, attendees could bypass the WAF and "prove" an attack that the WAF never saw. Private-only backend = honest lab.

---

<a name="architecture"></a>
## Reference architecture

```
                 Internet
                    │
                    ▼
        ┌───────────────────────┐
        │   Public IP (Std)     │  pip-waf-lab
        └───────────┬───────────┘
                    ▼
   ┌────────────────────────────────────┐
   │  Application Gateway  WAF_v2        │  agw-waf-lab
   │  ├─ Listener :80                    │
   │  ├─ WAF Policy (DRS 2.2)  ◀── wafpol-waf-lab
   │  │    mode: Detection → Prevention  │
   │  │    custom rules (Lab 6)          │
   │  └─ Backend pool ─────────────┐     │
   └──────────────────────────────┼─────┘
        snet-appgw 10.0.1.0/24     │
                                   ▼
                    ┌──────────────────────────┐
                    │  VM (private only)        │  vm-juice
                    │  Docker: Juice Shop :3000 │
                    └──────────────────────────┘
                       snet-backend 10.0.2.0/24
                    
   Diagnostic logs (AzureDiagnostics + resource-specific)
                    │
                    ▼
        ┌───────────────────────┐
        │  Log Analytics        │  law-waf-lab
        │  → KQL, Alerts,       │
        │    Workbook,          │
        │    Security Copilot   │
        └───────────────────────┘
```

**Data flow to teach:** request → public IP → gateway listener → **WAF evaluation** (custom rules first, then managed rules with anomaly scoring) → allow to backend **or** log/block → diagnostic logs stream to Log Analytics → KQL and Security Copilot read those logs.

---

# DAY 1

<a name="lab1"></a>
## Lab 1 — Build the network and backend

**Goal:** a VNet with two subnets, and a private VM running OWASP Juice Shop on port 3000.
**Time:** ~75 min. **Outcome:** `curl` from inside the VNet returns the Juice Shop page; the VM has no public IP.

### 1.1 Create the resource group

**Portal**
1. Portal → **Resource groups** → **Create**.
2. Subscription = yours, **Resource group** = `rg-waf-lab`, **Region** = East US → **Review + create** → **Create**.

**CLI**
```bash
az group create --name $RG --location $LOC
```

### 1.2 Create the virtual network and subnets

**Portal**
1. **Create a resource** → **Virtual network**.
2. Basics: RG `rg-waf-lab`, Name `vnet-waf-lab`, Region East US.
3. IP addresses: address space `10.0.0.0/16`. Add two subnets:
   - `snet-appgw` = `10.0.1.0/24`
   - `snet-backend` = `10.0.2.0/24`
4. **Review + create** → **Create**.

**CLI**
```bash
az network vnet create \
  --resource-group $RG --name $VNET \
  --address-prefix 10.0.0.0/16 \
  --subnet-name $SNET_AGW --subnet-prefix 10.0.1.0/24

az network vnet subnet create \
  --resource-group $RG --vnet-name $VNET \
  --name $SNET_BE --address-prefix 10.0.2.0/24
```

> **Gotcha:** the App Gateway subnet must be **dedicated** — no other resource types in `snet-appgw`. That is why the VM goes in `snet-backend`.

### 1.3 Create the backend VM (no public IP)

**Portal**
1. **Create a resource** → **Ubuntu Server 22.04 LTS** VM.
2. Basics: RG `rg-waf-lab`, Name `vm-juice`, Region East US, Size **B2s**, auth **SSH public key** (or password for lab speed), username `azureuser`.
3. Networking: VNet `vnet-waf-lab`, Subnet `snet-backend`, **Public IP = None**, NIC NSG = Basic, allow **SSH (22)** from your IP only (for setup).
4. **Review + create** → **Create**.

**CLI**
```bash
az vm create \
  --resource-group $RG --name $VM \
  --image Ubuntu2204 --size Standard_B2s \
  --vnet-name $VNET --subnet $SNET_BE \
  --public-ip-address "" \
  --admin-username $ADMIN --generate-ssh-keys \
  --nsg-rule SSH
```
The `--public-ip-address ""` flag is what keeps the VM private.

### 1.4 Install Docker and run Juice Shop

Because the VM is private, reach it with **`az vm run-command`** (no SSH exposure needed) — a nice teaching point on managing private hosts.

**CLI (works for both paths)**
```bash
az vm run-command invoke \
  --resource-group $RG --name $VM \
  --command-id RunShellScript \
  --scripts "
    sudo apt-get update -y &&
    sudo apt-get install -y docker.io &&
    sudo systemctl enable --now docker &&
    sudo docker run -d --restart always -p 3000:3000 --name juice bkimminich/juice-shop
  "
```

### 1.5 Verify the backend privately

```bash
# Get the VM's private IP
export BE_IP=$(az vm list-ip-addresses -g $RG -n $VM \
  --query "[0].virtualMachine.network.privateIpAddresses[0]" -o tsv)
echo "Backend private IP: $BE_IP"

# Curl Juice Shop from inside the VM (through run-command)
az vm run-command invoke -g $RG -n $VM \
  --command-id RunShellScript \
  --scripts "curl -s -o /dev/null -w '%{http_code}\n' http://localhost:3000"
```
A `200` confirms Juice Shop is up. **Checkpoint:** the app works, and it is not reachable from the internet — only from inside the VNet.

---

<a name="lab2"></a>
## Lab 2 — Deploy Application Gateway WAF_v2 in Detection mode

**Goal:** stand up `agw-waf-lab` (WAF_v2) with a WAF policy (DRS 2.2, **Detection**), pointing at the private VM.
**Time:** ~90 min (gateway provisioning is ~6–8 min — narrate concepts while it builds).
**Outcome:** browsing the gateway's public IP shows Juice Shop; the WAF is watching but not blocking.

### 2.1 Create the WAF policy first (DRS 2.2, Detection)

**Portal**
1. **Create a resource** → search **WAF** → **Web Application Firewall (WAF)**.
2. Basics: Policy for = **Regional WAF (Application Gateway)**, RG `rg-waf-lab`, Name `wafpol-waf-lab`.
3. **Policy settings** tab: **Mode = Detection**. Leave state Enabled.
4. **Managed rules** tab: Rule set = **Microsoft_DefaultRuleSet 2.2**. Leave defaults.
5. **Review + create** → **Create**. (You will associate it to the gateway in 2.3.)

**CLI**
```bash
# Create WAF policy
az network application-gateway waf-policy create \
  --resource-group $RG --name $WAFPOL

# Set mode to Detection and attach the managed rule set DRS 2.2
az network application-gateway waf-policy policy-setting update \
  --resource-group $RG --policy-name $WAFPOL \
  --mode Detection --state Enabled

az network application-gateway waf-policy managed-rule rule-set add \
  --resource-group $RG --policy-name $WAFPOL \
  --type Microsoft_DefaultRuleSet --version 2.2
```

### 2.2 Create the public IP

**Portal:** **Create a resource** → **Public IP address**, Name `pip-waf-lab`, SKU **Standard**, Assignment **Static**, RG `rg-waf-lab`.

**CLI**
```bash
az network public-ip create \
  --resource-group $RG --name $PIP \
  --sku Standard --allocation-method Static
```

### 2.3 Create the Application Gateway (WAF_v2) with the policy attached

**Portal**
1. **Create a resource** → **Application Gateway**.
2. Basics: RG `rg-waf-lab`, Name `agw-waf-lab`, Tier = **WAF V2**, **Enable autoscaling** (min 0, max 2), Region East US, VNet `vnet-waf-lab`, Subnet `snet-appgw`.
3. Under **WAF policy**, select the existing `wafpol-waf-lab`.
4. Frontends: Public, choose `pip-waf-lab`.
5. Backends: **Add a backend pool** `bp-juice` → target type **IP address**, value = the VM's private IP (`$BE_IP`).
6. Configuration → **Add a routing rule** `rule-80`:
   - Listener: `l-80`, Frontend Public, Port **80**, Protocol HTTP.
   - Backend targets: pool `bp-juice`; **HTTP settings** → new `hs-3000`, port **3000**, protocol HTTP.
7. **Review + create** → **Create** (~6–8 min).

**CLI**
```bash
az network application-gateway create \
  --resource-group $RG --name $AGW \
  --location $LOC \
  --sku WAF_v2 --priority 100 \
  --public-ip-address $PIP \
  --vnet-name $VNET --subnet $SNET_AGW \
  --servers $BE_IP \
  --http-settings-port 3000 --http-settings-protocol Http \
  --frontend-port 80 \
  --waf-policy $WAFPOL \
  --min-capacity 0 --max-capacity 2
```

### 2.4 Verify the path works through the WAF

```bash
export AGW_IP=$(az network public-ip show -g $RG -n $PIP --query ipAddress -o tsv)
echo "Gateway public IP: $AGW_IP"
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://$AGW_IP/
```
Open `http://$AGW_IP/` in a browser → Juice Shop loads. **Checkpoint:** traffic now flows Internet → WAF → private backend. Nothing is being blocked yet (Detection mode).

---

<a name="lab3"></a>
## Lab 3 — Wire diagnostics to Log Analytics

**Goal:** stream WAF logs to `law-waf-lab` so every downstream capability (KQL, alerts, workbook, Security Copilot) has data.
**Time:** ~75 min. **Outcome:** WAF firewall logs appear in Log Analytics within ~5–10 min of traffic.

> **Critical for Lab 8:** send logs to **both** the classic `AzureDiagnostics` table **and** resource-specific tables. The Security Copilot WAF skills currently do **not** work if you migrate to *only* dedicated tables — keep AzureDiagnostics enabled as well.

### 3.1 Create the Log Analytics workspace

**Portal:** **Create a resource** → **Log Analytics workspace**, RG `rg-waf-lab`, Name `law-waf-lab`, Region East US.

**CLI**
```bash
az monitor log-analytics workspace create \
  --resource-group $RG --workspace-name $LAW

export LAW_ID=$(az monitor log-analytics workspace show \
  -g $RG -n $LAW --query id -o tsv)
```

### 3.2 Enable diagnostic settings on the gateway

**Portal**
1. Go to `agw-waf-lab` → **Monitoring → Diagnostic settings** → **Add diagnostic setting**.
2. Name `diag-agw`. Categories: check **Application Gateway Firewall Log** and **Application Gateway Access Log** (add Performance if you like).
3. Destination: **Send to Log Analytics workspace** → `law-waf-lab`.
4. Toggle **destination table**: for this lab keep **Azure diagnostics** (so Security Copilot works).
5. **Save**.

**CLI**
```bash
export AGW_ID=$(az network application-gateway show -g $RG -n $AGW --query id -o tsv)

az monitor diagnostic-settings create \
  --name diag-agw \
  --resource $AGW_ID \
  --workspace $LAW_ID \
  --logs '[
    {"category":"ApplicationGatewayFirewallLog","enabled":true},
    {"category":"ApplicationGatewayAccessLog","enabled":true}
  ]' \
  --export-to-resource-specific false
```
`--export-to-resource-specific false` keeps the classic `AzureDiagnostics` table (Copilot-compatible). To also emit resource-specific tables, run a second setting with `true`.

### 3.3 Generate a little traffic and confirm ingestion

```bash
for i in $(seq 1 20); do curl -s -o /dev/null http://$AGW_IP/; done
```
Wait ~5–10 min, then in **Log Analytics → Logs** run:
```kql
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where Category == "ApplicationGatewayAccessLog"
| take 20
```
**Checkpoint:** rows appear. You now have the observability foundation for the rest of the course.

---

# DAY 2

<a name="lab4"></a>
## Lab 4 — Attack testing and reading the logs

**Goal:** fire representative OWASP attacks at the gateway in Detection mode, then find each one in the logs and map it to the rule that caught it.
**Time:** ~70 min. **Outcome:** attendees can go from "a request" to "which rule, what severity, what anomaly score."

> All tests below run in **Detection mode** — nothing is blocked, everything is logged. This is the safe way to see coverage before enforcing.

### 4.1 Baseline (benign) request
```bash
curl -s -o /dev/null -w "benign  -> HTTP %{http_code}\n" "http://$AGW_IP/"
```

### 4.2 SQL injection (rule family 942xxx)
```bash
curl -s -o /dev/null -w "sqli    -> HTTP %{http_code}\n" \
  "http://$AGW_IP/rest/products/search?q=test%27%20OR%20%271%27%3D%271"
# decoded: q=test' OR '1'='1
```

### 4.3 Cross-site scripting (rule family 941xxx)
```bash
curl -s -o /dev/null -w "xss     -> HTTP %{http_code}\n" \
  "http://$AGW_IP/?search=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
# decoded: search=<script>alert(1)</script>
```

### 4.4 Path traversal / LFI (rule family 930xxx)
```bash
curl -s -o /dev/null -w "lfi     -> HTTP %{http_code}\n" \
  "http://$AGW_IP/?file=../../../../etc/passwd"
```

### 4.5 Remote command execution attempt (rule family 932xxx)
```bash
curl -s -o /dev/null -w "rce     -> HTTP %{http_code}\n" \
  "http://$AGW_IP/?cmd=%2Fbin%2Fcat%20%2Fetc%2Fpasswd"
```

In Detection mode you will see **HTTP 200** for all of these (traffic passes) but each is **logged**. That is the teaching moment: *detection sees, prevention stops.*

### 4.6 Find the attacks in the logs
In **Log Analytics → Logs**:
```kql
AzureDiagnostics
| where Category == "ApplicationGatewayFirewallLog"
| where TimeGenerated > ago(30m)
| project TimeGenerated, action_s, ruleId_s, Message, details_data_s, clientIp_s
| order by TimeGenerated desc
```
Map what you see:
- `ruleId_s` starting **942** → SQLi; **941** → XSS; **930** → path traversal; **932** → RCE.
- `action_s` = **Matched** (a rule contributed to the anomaly score) and, when the score ≥ 5, a paired **Detected** entry (would be **Blocked** in Prevention).

**Anomaly scoring recap to voice here:** each matched rule adds to a score by severity (Critical 5, Error 4, Warning 3, Notice 2). At **score ≥ 5**, the WAF acts — logs in Detection, blocks in Prevention. One Critical match is enough on its own.

---

<a name="lab5"></a>
## Lab 5 — Tuning: exclusions and false positives

**Goal:** create a deliberate false positive, see it in the logs, then tune it away with an exclusion — without weakening protection globally.
**Time:** ~60 min. **Outcome:** attendees understand exclusions vs. disabling rules, and why you tune in Detection first.

### 5.1 Trigger a benign-but-flagged request
Some legitimate inputs look like attacks (e.g., a comment field containing `SELECT` or an apostrophe). Simulate one:
```bash
curl -s -o /dev/null -w "fp      -> HTTP %{http_code}\n" \
  "http://$AGW_IP/rest/products/search?q=O%27Brien%20SELECT%20books"
```
Find it in the firewall log (Lab 4 KQL). Note the `ruleId_s` that fired (often a 942xxx SQLi rule reacting to the apostrophe/keyword).

### 5.2 Add a targeted exclusion

**Portal**
1. `wafpol-waf-lab` → **Managed rules** → **Exclusions** → **Add exclusion**.
2. Match variable = **RequestArgNames**, Operator = **Equals**, Selector = `q`.
3. Save. This excludes the `q` query argument from managed-rule evaluation.

**CLI**
```bash
az network application-gateway waf-policy managed-rule exclusion add \
  --resource-group $RG --policy-name $WAFPOL \
  --match-variable RequestArgNames \
  --selector-match-operator Equals \
  --selector q
```

### 5.3 Prove the tuning worked
Re-run the 5.1 request → it should no longer match (no new firewall-log entry for that rule). Re-run a **real** SQLi against a *different* parameter (Lab 4.2) → still detected. **Teaching point:** exclusions are **scoped** (this argument, this header), so you keep coverage everywhere else. Prefer a scoped exclusion over disabling a rule set-wide.

> **Order of preference for false positives:** (1) scoped exclusion → (2) disable a single rule ID → (3) lower paranoia / change rule action → (4) never disable an entire rule group unless you truly must.

---

<a name="lab6"></a>
## Lab 6 — Custom rules (rate-limit, geo, IP, header)

**Goal:** author the four most common custom rules. These run **before** managed rules and are how you express business/security policy the managed set can't.
**Time:** ~75 min. **Outcome:** four working custom rules, verified.

### 6.1 IP block (deny a known-bad range)

**Portal:** `wafpol-waf-lab` → **Custom rules** → **Add custom rule**: Name `block-badip`, Priority `10`, Rule type **Match**, Condition: Match variable **RemoteAddr**, Operator **IPMatch**, Values `192.0.2.0/24`, Action **Deny**.

**CLI**
```bash
az network application-gateway waf-policy custom-rule create \
  --resource-group $RG --policy-name $WAFPOL \
  --name blockBadIp --priority 10 --rule-type MatchRule --action Block
az network application-gateway waf-policy custom-rule match-condition add \
  --resource-group $RG --policy-name $WAFPOL --name blockBadIp \
  --match-variables RemoteAddr --operator IPMatch --values 192.0.2.0/24
```

### 6.2 Geo-filter (allow only selected countries, or block a country)

**CLI (block by country code)**
```bash
az network application-gateway waf-policy custom-rule create \
  --resource-group $RG --policy-name $WAFPOL \
  --name geoBlock --priority 20 --rule-type MatchRule --action Block
az network application-gateway waf-policy custom-rule match-condition add \
  --resource-group $RG --policy-name $WAFPOL --name geoBlock \
  --match-variables RemoteAddr --operator GeoMatch --values "KP" "RU"
```

### 6.3 Rate limit (throttle abusive clients)

**Portal:** Add custom rule, Rule type **Rate limit**, Rate limit duration **1 minute**, Threshold **100**, Group-by **ClientAddr**, a match condition of RequestUri **Contains** `/`, Action **Block**.

**CLI**
```bash
az network application-gateway waf-policy custom-rule create \
  --resource-group $RG --policy-name $WAFPOL \
  --name rateLimit --priority 30 --rule-type RateLimitRule \
  --action Block --rate-limit-duration OneMin --rate-limit-threshold 100 \
  --group-by-user-session '[{"groupByVariables":[{"variableName":"ClientAddr"}]}]'
az network application-gateway waf-policy custom-rule match-condition add \
  --resource-group $RG --policy-name $WAFPOL --name rateLimit \
  --match-variables RequestUri --operator Contains --values "/"
```

### 6.4 Header check (require an API key on an API path)

**CLI**
```bash
az network application-gateway waf-policy custom-rule create \
  --resource-group $RG --policy-name $WAFPOL \
  --name requireApiKey --priority 40 --rule-type MatchRule --action Block
# Block requests to /rest/ that do NOT carry a specific header value (negated match)
az network application-gateway waf-policy custom-rule match-condition add \
  --resource-group $RG --policy-name $WAFPOL --name requireApiKey \
  --match-variables RequestHeaders=X-Api-Key --operator Equal \
  --values "lab-secret-key" --negate true
```

### 6.5 Verify
```bash
# Rate limit: hammer the endpoint and watch for throttling once in Prevention
for i in $(seq 1 150); do curl -s -o /dev/null -w "%{http_code} " http://$AGW_IP/; done; echo
```
In Detection these are logged; after Lab 7 (Prevention) the deny/rate-limit rules actually block. **Teaching point:** custom rules are evaluated by **priority (low number first)** and short-circuit — the first Allow/Block wins and managed rules downstream are skipped for that request.

---

<a name="lab7"></a>
## Lab 7 — Enforce Prevention and re-test

**Goal:** flip the policy to **Prevention** and watch the same attacks now get blocked.
**Time:** ~45 min. **Outcome:** the before/after that makes WAF value obvious.

### 7.1 Switch the mode

**Portal:** `wafpol-waf-lab` → **Policy settings** → Mode = **Prevention** → Save.

**CLI**
```bash
az network application-gateway waf-policy policy-setting update \
  --resource-group $RG --policy-name $WAFPOL --mode Prevention
```

### 7.2 Re-run the attack suite
```bash
curl -s -o /dev/null -w "benign  -> HTTP %{http_code}\n" "http://$AGW_IP/"
curl -s -o /dev/null -w "sqli    -> HTTP %{http_code}\n" "http://$AGW_IP/rest/products/search?q=test%27%20OR%20%271%27%3D%271"
curl -s -o /dev/null -w "xss     -> HTTP %{http_code}\n" "http://$AGW_IP/?search=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
curl -s -o /dev/null -w "lfi     -> HTTP %{http_code}\n" "http://$AGW_IP/?file=../../../../etc/passwd"
```
Now the benign request returns **200** and the attacks return **403** (blocked). In the firewall log, `action_s` is now **Blocked**. **This is the money slide/demo of the course.**

### 7.3 Discuss the operating model
- You always land in **Detection**, tune for days/weeks against real traffic, *then* enforce **Prevention**.
- Governance (Lab 9) ensures new gateways can't ship stuck in Detection.

---

<a name="lab8"></a>
## Lab 8 — Security Copilot for WAF

**Goal:** investigate the WAF events you just generated using natural language instead of hand-written KQL.
**Time:** ~75 min. **Outcome:** attendees run the four WAF skills and understand enablement, cost, and the logging caveat.

> **What it is:** the **Azure Web Application Firewall integration in Microsoft Security Copilot** — a first-party plugin (distinct from *Copilot in Azure*, the general portal assistant). It reads your WAF logs from Log Analytics and answers investigation questions in plain language. Works with **both** WAF on Application Gateway and WAF on Front Door.

### 8.1 Prerequisites
- Security Copilot provisioned with **≥ 1 SCU** (see cost section). Check for an **M365 E5/E7 inclusion pool** first — you may already have SCUs.
- **Copilot contributor** permissions.
- WAF logs flowing to `law-waf-lab` (Lab 3) — and **AzureDiagnostics** enabled (the skills break on dedicated-tables-only).

### 8.2 Enable the plugin
1. Go to **https://securitycopilot.microsoft.com**.
2. Open the menu → **Sources** in the prompt bar (the Plugins page).
3. Set **Azure Web Application Firewall** to **On**.
4. Open the plugin **Settings** → point it at the **Log Analytics workspace** holding your WAF logs (`law-waf-lab`).
5. Start prompting.

### 8.3 The four WAF skills — sample prompts
Run these against the traffic from Labs 4 and 7:
- **Top triggered rules:** "Show me the top WAF rules triggered in my regional WAF in the last 24 hours."
- **Top offending IPs:** "What are the top offending IP addresses my Application Gateway WAF blocked today, and why?"
- **SQLi summary:** "Summarize the SQL injection attacks blocked by my WAF in the last 12 hours."
- **XSS summary:** "Summarize the cross-site scripting attacks blocked by my WAF in the last 12 hours."

Each returns a natural-language explanation — *what attacked you, from where, and why it was blocked* — instead of raw log rows. Great for handing a junior analyst.

### 8.4 Caveat to state out loud
If a customer has migrated their App Gateway WAF logs to **dedicated Log Analytics tables only**, the Copilot WAF skills won't function. Workaround: also enable **Azure Diagnostics** as a destination table (as we did in Lab 3). Application Gateway **for Containers** WAF does not support Security Copilot.

### 8.5 Same steps at the customer
Identical flow in their tenant: Security Copilot provisioned, plugin permissions, and their WAF already logging to a workspace you can select. Nothing lab-specific.

---

<a name="lab9"></a>
## Lab 9 — Governance, alerting, and workbooks

**Goal:** make the WAF operable — alert on block spikes, visualize with a workbook, and enforce via Azure Policy.
**Time:** ~45 min. **Outcome:** an alert rule, a starter workbook query, and a policy that prevents Detection-only gateways.

### 9.1 Alert on a spike in blocks

**CLI (scheduled query alert)**
```bash
az monitor scheduled-query create \
  --resource-group $RG --name "alert-waf-block-spike" \
  --scopes $LAW_ID \
  --condition "count 'Placeholder' > 50" \
  --condition-query Placeholder='AzureDiagnostics | where Category=="ApplicationGatewayFirewallLog" | where action_s=="Blocked"' \
  --evaluation-frequency 5m --window-size 15m \
  --severity 2 --description "WAF blocked-request spike"
```
(Portal path: Log Analytics → **Alerts** → **New alert rule** → use the blocked-requests KQL, threshold, action group.)

### 9.2 Workbook / dashboard query
Add this to a new **Azure Workbook** (Monitoring → Workbooks → New → Query):
```kql
AzureDiagnostics
| where Category == "ApplicationGatewayFirewallLog"
| summarize count() by action_s, bin(TimeGenerated, 5m)
| render timechart
```

### 9.3 Governance with Azure Policy
Assign a built-in policy so new Application Gateways must have WAF enabled (and, via custom policy, be in Prevention). Search the Policy blade for **"Web Application Firewall (WAF) should be enabled for Azure Application Gateway"** and assign it at the subscription/RG scope. Discuss `Audit` vs `Deny` effects.

---

<a name="use-cases"></a>
## Use cases (mapped to the labs)

| # | Use case | What it protects against | Lab that proves it |
|---|---|---|---|
| 1 | Block OWASP Top 10 web attacks | SQLi, XSS, LFI/RFI, RCE | Labs 4, 7 |
| 2 | Detection-first rollout | Enforcing blindly and breaking prod | Labs 2, 7 |
| 3 | Tune false positives without losing coverage | Over-blocking legit traffic | Lab 5 |
| 4 | Block known-bad IPs / geographies | Botnets, embargoed regions | Lab 6.1, 6.2 |
| 5 | Rate-limit credential stuffing / brute force | Login abuse, scraping | Lab 6.3 |
| 6 | Enforce API contract (required headers) | Unauthenticated API calls | Lab 6.4 |
| 7 | Investigate incidents at machine speed | Slow manual log triage | Lab 8 |
| 8 | Alert + visualize + govern | Silent drift, ungoverned gateways | Lab 9 |
| 9 | Global edge protection alternative | Multi-region/CDN-fronted apps | Appendix A (Front Door) |

---

<a name="cost"></a>
## Cost model

All figures USD, list price, `eastus`, **as of September 2026** — always confirm on the Azure Pricing pages before quoting a customer.

### Unit prices
| Component | Price |
|---|---|
| Application Gateway **WAF_v2** — fixed | **$0.443 / gateway-hour** |
| Application Gateway **WAF_v2** — capacity | **$0.0144 / capacity-unit-hour** |
| Public IP (Standard, static) | ~$0.005 / hour (~$3.65/mo) |
| Backend VM (B2s, Linux) | ~$0.0416 / hour |
| Log Analytics ingestion | ~$2.76 / GB after 5 GB/mo free (lab volume ≈ free) |
| **Security Copilot** | **$4.00 / SCU-hour provisioned** (min 1 SCU); $6 overage; E5/E7 inclusion pool = 0.4 SCU/paid license/mo |
| Front Door **Standard** (alt.) | $35 / month (custom rules only) |
| Front Door **Premium** (alt.) | $330 / month (managed rules bundled) |

### Lab cost scenarios

**A — Single shared environment, running only during class (16 hrs over 2 days):**
| Item | Rate | Hrs | Cost |
|---|---|---|---|
| WAF_v2 fixed | $0.443 | 16 | $7.09 |
| WAF_v2 capacity (~5 CU avg) | $0.072 | 16 | $1.15 |
| Public IP | $0.005 | 16 | $0.08 |
| VM B2s | $0.0416 | 16 | $0.67 |
| Log Analytics | — | — | ~$0 (free tier) |
| **Subtotal (no Copilot)** | | | **≈ $9** |

**B — Left running 24/7 across the two days (~48 hrs):** ≈ **$27**.

**C — Add Security Copilot demo (1 SCU, provisioned ~3 hrs total, then de-provisioned):** **+$12**.
> ⚠️ The SCU meter runs 24/7 while provisioned. Forgetting to de-provision 1 SCU for a day = **$96**. **De-provision immediately after Lab 8.** If the tenant has an E5/E7 inclusion pool, the demo may cost **$0**.

**D — Per-attendee build (each of N attendees runs their own gateway during hands-on ~6 hrs/day):**
≈ **$3.30/attendee/day** for the gateway+VM+IP; e.g., 8 attendees × 2 days ≈ **$53** total. Prefer one shared environment for cost, or per-attendee for muscle memory.

### Realistic total for your presenter sandbox (disciplined teardown)
**≈ $20–25** for the full two days including a short Copilot demo — contingent on **deleting the resource group** and **de-provisioning SCUs** at the end of each day.

---

<a name="troubleshooting"></a>
## Troubleshooting playbook

| Symptom | Likely cause | Fix |
|---|---|---|
| Gateway shows **502 Bad Gateway** | Backend health probe failing; Juice Shop not on :3000; HTTP setting port wrong | `az vm run-command` curl localhost:3000; confirm HTTP setting port = 3000; check NSG allows gateway subnet → backend :3000 |
| Browsing gateway IP times out | Public IP not associated / listener not on :80 / NSG on appgw subnet blocks 65200-65535 | Confirm listener port 80; App Gateway subnet must allow inbound **65200–65535** (gateway management) |
| Attacks return 200 in "Prevention" | Policy still in Detection, or not associated to the gateway | Confirm `mode=Prevention` **and** the policy is attached to the gateway/listener |
| No rows in Log Analytics | Diagnostic setting missing/wrong category; <10 min lag | Re-check `diag-agw`; generate traffic; wait 10 min |
| Security Copilot returns nothing | Logs only in dedicated tables; wrong workspace selected; no SCU | Enable **AzureDiagnostics** table; point plugin at `law-waf-lab`; provision ≥1 SCU |
| Legit traffic blocked | False positive on a managed rule | Add a **scoped exclusion** (Lab 5), not a global disable |
| Custom rule "not working" | Priority order / short-circuit; Detection mode | Lower priority number = evaluated first; verify Prevention mode |
| Gateway stuck provisioning / can't delete subnet | App Gateway subnet not dedicated | Ensure only the gateway lives in `snet-appgw` |

---

<a name="teardown"></a>
## Teardown

**Delete everything (one command):**
```bash
az group delete --name $RG --yes --no-wait
```

**De-provision Security Copilot SCUs (do this separately — they are not in the RG):**
Security Copilot → **Owner settings / Capacity** → set provisioned SCUs to the minimum or delete the `microsoft.securitycopilot/capacities` resource. **Confirm the meter has stopped.**

**Verify nothing lingers:**
```bash
az group exists --name $RG        # should return false after deletion completes
```

Rebuild next morning from **Appendix C** in ~10 minutes.

---

<a name="appendix-a"></a>
## Appendix A — Front Door WAF alternative (global edge)

When the customer's apps are **multi-region or CDN-fronted**, WAF on **Azure Front Door Premium** is the better fit — protection at the global edge instead of per-VNet.

| | App Gateway WAF_v2 | Front Door WAF (Premium) |
|---|---|---|
| Scope | Regional, per-VNet ingress | Global edge / anycast |
| Pricing model | Per gateway-hour + capacity-unit-hour | Bundled into tier ($330/mo Premium) |
| Managed rules | DRS 2.2 | DRS 2.2 (Premium) |
| Best for | Apps already fronted by App Gateway | Global apps, CDN, multi-region |
| Rate limiting granularity | Per client | Per client at edge |

**Minimal CLI to show the alternative:**
```bash
az afd profile create -g $RG --profile-name afd-waf-lab --sku Premium_AzureFrontDoor
az network front-door waf-policy create -g $RG -n fdwafpol --sku Premium_AzureFrontDoor --mode Detection
# associate managed DRS 2.2, then attach the policy to a Front Door security policy/endpoint
```
Teach the decision, don't necessarily build the whole thing live — App Gateway WAF is the anchor lab.

---

<a name="appendix-b"></a>
## Appendix B — KQL query pack

```kql
// 1. All firewall events, newest first
AzureDiagnostics
| where Category == "ApplicationGatewayFirewallLog"
| project TimeGenerated, action_s, ruleId_s, Message, clientIp_s, requestUri_s
| order by TimeGenerated desc

// 2. Blocked vs matched over time
AzureDiagnostics
| where Category == "ApplicationGatewayFirewallLog"
| summarize count() by action_s, bin(TimeGenerated, 5m)
| render timechart

// 3. Top triggered rules
AzureDiagnostics
| where Category == "ApplicationGatewayFirewallLog"
| summarize hits=count() by ruleId_s
| top 15 by hits desc

// 4. Top offending client IPs
AzureDiagnostics
| where Category == "ApplicationGatewayFirewallLog"
| where action_s in ("Blocked","Detected")
| summarize hits=count() by clientIp_s
| top 15 by hits desc

// 5. Attack family breakdown (by rule prefix)
AzureDiagnostics
| where Category == "ApplicationGatewayFirewallLog"
| extend family = case(
    ruleId_s startswith "942","SQLi",
    ruleId_s startswith "941","XSS",
    ruleId_s startswith "930","PathTraversal/LFI",
    ruleId_s startswith "932","RCE",
    "Other")
| summarize count() by family
| render piechart
```

---

<a name="appendix-c"></a>
## Appendix C — Full deploy script (copy-paste)

Run top to bottom in Cloud Shell to build the whole presenter sandbox in ~10–15 minutes (gateway provisioning dominates). Sets Detection mode; flip to Prevention in Lab 7.

```bash
#!/usr/bin/env bash
set -euo pipefail

# ---- variables ----
export RG="rg-waf-lab" LOC="eastus" VNET="vnet-waf-lab"
export SNET_AGW="snet-appgw" SNET_BE="snet-backend"
export PIP="pip-waf-lab" AGW="agw-waf-lab" WAFPOL="wafpol-waf-lab"
export VM="vm-juice" LAW="law-waf-lab" ADMIN="azureuser"

# ---- resource group + network ----
az group create -n $RG -l $LOC
az network vnet create -g $RG -n $VNET --address-prefix 10.0.0.0/16 \
  --subnet-name $SNET_AGW --subnet-prefix 10.0.1.0/24
az network vnet subnet create -g $RG --vnet-name $VNET -n $SNET_BE --address-prefix 10.0.2.0/24

# ---- backend VM (private) + Juice Shop ----
az vm create -g $RG -n $VM --image Ubuntu2204 --size Standard_B2s \
  --vnet-name $VNET --subnet $SNET_BE --public-ip-address "" \
  --admin-username $ADMIN --generate-ssh-keys --nsg-rule SSH
az vm run-command invoke -g $RG -n $VM --command-id RunShellScript --scripts \
  "sudo apt-get update -y && sudo apt-get install -y docker.io && sudo systemctl enable --now docker && sudo docker run -d --restart always -p 3000:3000 --name juice bkimminich/juice-shop"
export BE_IP=$(az vm list-ip-addresses -g $RG -n $VM --query "[0].virtualMachine.network.privateIpAddresses[0]" -o tsv)

# ---- WAF policy (DRS 2.2, Detection) ----
az network application-gateway waf-policy create -g $RG -n $WAFPOL
az network application-gateway waf-policy policy-setting update -g $RG --policy-name $WAFPOL --mode Detection --state Enabled
az network application-gateway waf-policy managed-rule rule-set add -g $RG --policy-name $WAFPOL --type Microsoft_DefaultRuleSet --version 2.2

# ---- public IP + gateway ----
az network public-ip create -g $RG -n $PIP --sku Standard --allocation-method Static
az network application-gateway create -g $RG -n $AGW -l $LOC \
  --sku WAF_v2 --priority 100 --public-ip-address $PIP \
  --vnet-name $VNET --subnet $SNET_AGW --servers $BE_IP \
  --http-settings-port 3000 --http-settings-protocol Http --frontend-port 80 \
  --waf-policy $WAFPOL --min-capacity 0 --max-capacity 2

# ---- Log Analytics + diagnostics ----
az monitor log-analytics workspace create -g $RG --workspace-name $LAW
export LAW_ID=$(az monitor log-analytics workspace show -g $RG -n $LAW --query id -o tsv)
export AGW_ID=$(az network application-gateway show -g $RG -n $AGW --query id -o tsv)
az monitor diagnostic-settings create --name diag-agw --resource $AGW_ID --workspace $LAW_ID \
  --logs '[{"category":"ApplicationGatewayFirewallLog","enabled":true},{"category":"ApplicationGatewayAccessLog","enabled":true}]' \
  --export-to-resource-specific false

# ---- output ----
export AGW_IP=$(az network public-ip show -g $RG -n $PIP --query ipAddress -o tsv)
echo "Gateway public IP: http://$AGW_IP/  (Detection mode; flip to Prevention in Lab 7)"
```

---

*End of guide. Pair this with the presenter deck (Azure-WAF-2Day-Presenter-Deck.pptx). Verify all pricing and rule-set versions on Microsoft Learn and the Azure Pricing pages before customer delivery.*
