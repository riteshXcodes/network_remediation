import express from "express";
import fetch from "node-fetch";


/* =========================
   JIRA CONFIG
========================= */

const JIRA_BASE_URL = process.env.JIRA_BASE;
const JIRA_EMAIL = process.env.JIRA_MAIL;
const JIRA_API_TOKEN = process.env.JIRA_API;
const JIRA_PROJECT_KEY = process.env.JIRA_PROJECT;

async function createJiraTicket({ summary, description, priority = "Medium" }) {
  if (!JIRA_BASE_URL || !JIRA_EMAIL || !JIRA_API_TOKEN || !JIRA_PROJECT_KEY) {
    throw new Error("Jira environment variables missing");
  }

  const auth = Buffer.from(`${JIRA_EMAIL}:${JIRA_API_TOKEN}`).toString("base64");

  const payload = {
    fields: {
      project: { key: JIRA_PROJECT_KEY },
      summary,
      description,
      issuetype: { name: "Task" },
      priority: { name: priority },
      labels: ["threatpilot", "automated"]
    }
  };

  const res = await fetch(`${JIRA_BASE_URL}/rest/api/3/issue`, {
    method: "POST",
    headers: {
      "Authorization": `Basic ${auth}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  const data = await res.json();

  if (!res.ok) {
    console.error("Jira error:", data);
    throw new Error("Failed to create Jira ticket");
  }

  return data.key;
}


async function alertSRESlack(payload) {
  const webhook = process.env.SLACK_WEBHOOK_URL;

  if (!webhook) {
    throw new Error("Slack webhook not configured");
  }

  const message = {
    text: "🚨 *Security Alert – ThreatPilot*",
    blocks: [
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `*Threat:* ${payload.threat || "Unknown"}\n*Severity:* ${payload.severity || "Medium"}`
        }
      },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `*Target:* ${payload.target || "N/A"}\n*Recommended Action:* ${payload.action}`
        }
      },
      {
        type: "context",
        elements: [
          {
            type: "mrkdwn",
            text: `⏱ ${new Date().toISOString()}`
          }
        ]
      }
    ]
  };

  await fetch(webhook, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(message)
  });
}


async function blockIPCloudflare(ip) {
  const zoneId = process.env.CF_ZONE_ID;
  const apiToken = process.env.CF_API_TOKEN;

  if (!zoneId || !apiToken) {
    throw new Error("Cloudflare env vars missing");
  }

  const url = `https://api.cloudflare.com/client/v4/zones/${zoneId}/firewall/access_rules/rules`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiToken}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      mode: "block",
      configuration: {
        target: "ip",
        value: ip
      },
      notes: "ThreatPilot automated remediation"
    })
  });

  const data = await response.json();

  if (!data.success) {
    console.error("Cloudflare error:", data);
    throw new Error(data.errors?.[0]?.message || "Cloudflare block failed");
  }

  return data.result;
}


const app = express();
app.use(express.json());


/**
 * Single remediation endpoint
 * Agent yahin call karega
 */
app.post("/execute", async (req, res) => {
  try{
  const { action, target, severity = "medium" } = req.body;

  // Basic validation
  if (!action) {
    return res.status(400).json({
      status: "error",
      message: "Action is required"
    });
  }

  
  if (action === "block_ip") {
    
    // return res.json({
    //   status: "success",
    //   action_taken: "block_ip",
    //   target,
    //   method: "firewall_simulation",
    //   message: `IP ${target} blocked`,
    //   executed_at: new Date().toISOString()
    // });

    const rule = await blockIPCloudflare(target);

    return res.json({
      status: "success",
      action_taken: "block_ip",
      target,
      method: "cloudflare_firewall",
      cloudflare_rule_id: rule.id,
      message: `IP ${target} blocked via Cloudflare`,
      executed_at: new Date().toISOString()
    });
    
  }

      if (
      action === "rate_limit_ip" ||
      action === "add_waf_rule" ||
      action === "block_endpoint"
    ) {
      const jiraKey = await createJiraTicket({
        summary: `[ThreatPilot] ${action.replaceAll("_", " ").toUpperCase()}`,
        description: `Action: ${action}
Target: ${JSON.stringify(target, null, 2)}
Severity: ${severity}`,
        priority: severity === "high" ? "High" : "Medium"
      });

      return res.json({
        status: "pending_approval",
        action,
        target,
        jira_ticket: jiraKey
      });
    }

  if (action === "alert_sre") {
  await alertSRESlack(req.body);

  return res.json({
    status: "success",
    action_taken: "alert_sre",
    method: "slack_notification",
    message: "SRE alerted via Slack",
    executed_at: new Date().toISOString()
  });
}  

  // Fallback
  return res.status(400).json({
    status: "ignored",
    message: "Unsupported action"
  });

  }catch(err){
    console.error("❌ Remediation error:", err.message);

    return res.status(500).json({
      status: "error",
      message: err.message
    });
  }
});

// IMPORTANT: On-Demand uses PORT env var
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`HTTP Remediation Service running on port ${PORT}`);
});
