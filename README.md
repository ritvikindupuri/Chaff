# Chaff - Autonomous Bot Defense

**Autonomous bot-traffic analyst powered by AI and your Elasticsearch logs. Separate humans from bots.**

Chaff acts as your autonomous Tier-1 Security Analyst. Instead of staring at dashboards and raw logs, Chaff connects directly to your Elasticsearch instance, allowing an advanced AI Agent (powered by Gemini) to investigate scrapers, credential stuffing, and scanners in real-time. It provides actionable threat intelligence, creates automated honeypots, and helps you block malicious traffic at the edge.

[**Read the Full Technical Documentation**](./TECHNICAL_DOCUMENTATION.md)

---

## System Architecture

<div align="center">
  <h3>Chaff Data Flow & Architecture</h3>
</div>

```mermaid
graph TD
    %% User and UI Layer
    User((User / SecOps))
    UI[Frontend UI<br/>React, Vite, Tailwind]
    User -->|Interacts with| UI

    %% Application Server Layer
    Server[TanStack Server Functions<br/>Backend API]
    UI <-->|TanStack Query/Router| Server

    %% Authentication & Database Layer
    SupabaseDB[(Supabase PostgreSQL<br/>Auth, State, Config)]
    Server <-->|Fetch/Save Configs & Auth| SupabaseDB

    %% Core Services Layer
    ChaffAgent[Chaff AI Agent<br/>Gemini via Lovable Cloud]
    ESConnect[Elasticsearch Connector]
    FirecrawlApi[Firecrawl Integration<br/>Onboarding Site Scanner]
    MCPServer[MCP Server<br/>Model Context Protocol]

    %% Internal Connections
    Server <-->|AI Prompts & Tool Calling| ChaffAgent
    Server <-->|Query Logs & Analytics| ESConnect
    Server <-->|Scan Site During Onboarding| FirecrawlApi
    Server <-->|Context Queries| MCPServer

    %% External Data Sources
    CustomerES[(Customer Elasticsearch<br/>Raw Log Data)]
    ExternalWeb[External Web Targets]

    ESConnect <-->|Search DSL, Aggr, Samples| CustomerES
    FirecrawlApi <-->|Web Scraping| ExternalWeb
    ChaffAgent -->|Tool: search_logs, record_threat| Server
```

### Flow by Flow Explanation

1. **User Authentication & Initialization:** The User accesses the React frontend UI and is authenticated via Supabase. The user is prompted to connect their data source.
2. **Connecting to External Data:** The user inputs their Elasticsearch credentials. The server tests the connection and securely saves the configuration.
3. **Data Analysis via Chaff Agent:** The user queries the Chaff Agent. The Agent constructs a system prompt and loops through native tools (`search_logs`, `sample_requests`) to query the Customer's Elasticsearch logs directly via the backend server functions.
4. **Recording Threats:** The Agent identifies bots and records findings to the Supabase database using the `record_threat` tool. The React frontend visualizes these on the Dashboard.
5. **Honeypot Creation:** To proactively catch bots, Chaff creates unique trap URLs (a decoy pricing page served at `/trap/<slug>`) that you link invisibly from your site; any visit is flagged as a bot. Separately, Firecrawl scans your site during onboarding to detect its stack and exposed admin/login/API paths.
6. **Block Rules & Mitigation:** Identified threats result in Block Rules stored in Supabase, ready to be exported to external WAFs.
7. **Extensibility:** The MCP (Model Context Protocol) Server exposes threat intelligence context to local AI developer tools.

---

## Tech Stack

- **Frontend:** React, Vite, Tailwind CSS, TanStack (Router, Query, Start), Recharts, Radix UI, Framer Motion
- **Backend:** TanStack Server Functions, Node.js
- **Database & Auth:** Supabase (PostgreSQL, Edge Functions)
- **AI & Intelligence:** Lovable AI (Google Gemini 3 Flash Preview)
- **Log Integration:** Elasticsearch
- **External Scraper/Honeypot Integrations:** Firecrawl (`@mendable/firecrawl-js`)

---

## Detailed Setup Instructions

Follow these exact baby steps to get Chaff running on your local machine.

### 1. Clone the repository

Copy and paste the following commands into your terminal to clone the repository and navigate into the directory:

```bash
git clone https://github.com/lovable-dev/chaff.git
cd chaff
```

_(Note: adjust the repository URL to your exact remote URL if different)_

### 2. Install dependencies

Install all required Node packages using npm:

```bash
npm install
```

### 3. Configure environment

The standard `.env` file is auto-managed by Lovable Cloud and includes your Supabase connections. Ensure your environment has the following setup (you can check your `.env` template):

```
VITE_SUPABASE_URL=your_supabase_url
VITE_SUPABASE_PUBLISHABLE_KEY=your_supabase_anon_key
VITE_SUPABASE_PROJECT_ID=your_supabase_project_id
```

### 4. Add required secrets

To enable the Honeypot and web scraping functionalities, you must add the Firecrawl secret. In Lovable Cloud (or your local `.env`), add the following secret:

```
FIRECRAWL_API_KEY=your_firecrawl_api_key
```

### 5. Run the development server

Start the local Vite development server:

```bash
npm run dev
```

### 6. Access the App

Open `http://localhost:8080` (or the port provided by Vite in your terminal) in your web browser. Click the sign-in button and **Sign up with Google** to create an account and begin using Chaff.

### 7. Generate Test Bot Traffic (Optional)

To test Chaff's detection capabilities, you can simulate malicious bot traffic against your web application. Your web application must be logging requests to the Elasticsearch instance connected to Chaff.

Chaff automatically flags traffic from known bot User-Agents (like `python-requests`, `curl`, `puppeteer`, etc.) and identifies patterns like rapid burst requests or scanner behaviors.

Open a new terminal and run one of the following commands to generate test traffic:

**Option A: Simulate a Vulnerability Scanner**
This simulates a bot probing for sensitive paths using the `python-requests` User-Agent:
```bash
for path in "/admin" "/wp-admin" "/.env" "/config.json" "/login"; do
  curl -A "python-requests/2.28.1" "https://your-app.com$path"
  sleep 0.5
done
```

**Option B: Simulate Credential Stuffing / Burst Traffic**
This simulates a rapid burst of requests to a login endpoint using the `curl` User-Agent:
```bash
for i in {1..50}; do
  curl -X POST -A "curl/7.68.0" "https://your-app.com/login"
done
```

*(Note: Replace `https://your-app.com` with the actual URL of your application that is logging to Elasticsearch).*

Once the traffic is generated, go to the **Agent** tab in the Chaff UI and ask: _"Investigate recent traffic to /login. Are there any bot attacks?"_ The Agent will identify the bot traffic and record it in the **Threats** tab.

---

## How to Use the Application

This step-by-step walkthrough will guide you perfectly through using Chaff.

### Step 1: Initial Login

When you open the application in your browser, you will see a login screen. Click the **"Sign up with Google"** button to authenticate and access the dashboard.

### Step 2: Activate Chaff (Connecting Elasticsearch)

Upon first login, the Agent cannot function without data.

1. Navigate to the **"Onboard"** tab (or click the **Activate Chaff** button if prompted by the empty state).
2. Enter your Elasticsearch credentials:
   - **Endpoint URL** (e.g., `https://your-cluster.es.us-central1.gcp.cloud.es.io:9243`)
   - **API Key**
   - **Index Pattern** (e.g., `logs-web-*` or `filebeat-*`)
   - **Field Mappings:** Ensure the fields for IP (`client.ip`), User-Agent (`user_agent.original`), URL/Path (`url.path`), Timestamp (`@timestamp`), and Status Code (`http.response.status_code`) match your Elasticsearch schema.
3. Click to save and test the connection.

### Step 3: Utilize the Chaff Agent

With data flowing, it's time to investigate.

1. Click on the **"Agent"** tab in the sidebar.
2. You will be greeted by the Chaff AI. You can click on a suggested prompt like _"Investigate any unusual spikes in the last 24h"_ or type your own question.
3. The Agent will autonomously execute tools, fetch real logs from your connected Elasticsearch instance, and return a comprehensive report classifying bots and identifying specific IP addresses.
4. If the Agent identifies a severe threat, it will automatically record it to your system.

### Step 4: Review Threats

1. Click on the **"Threats"** tab to view your dashboard.
2. Here, you will see visual charts of your traffic, distinguishing between "Human" and "Bot" requests.
3. Below the charts, review the list of recorded threats identified by the Agent, including their severity, origin IP, and the exact tools used by the bots.

### Step 5: Deploy Honeypots

1. Click on the **"Honeypots"** tab.
2. Enter a label and click **New trap** to create a unique trap URL (a decoy pricing page).
3. Share the trap URL where only crawlers will find it (sitemap, robots.txt, hidden links). Any traffic that hits these hidden URLs will be immediately flagged as malicious in your dashboard.

### Step 6: Create Campaigns & MCP

- **Campaigns:** Navigate to the **Campaigns** tab and click **Re-cluster** to group related bot activity into campaigns, then track them, mark them as monitoring or resolved, and export block rules.
- **MCP:** Use the **MCP** tab to expose Chaff's threat intelligence context directly to external AI assistants (like Cursor), enabling you to ask your local IDE questions about active threats.

### Step 7: Live View

- **Live:** Click the **Live** tab to see real-time unaggregated log activity flowing directly from your Elasticsearch instance.

---

## License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT) - an OSI-approved open source license.
