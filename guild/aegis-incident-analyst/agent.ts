// AEGIS incident analyst: turns a structured incident summary from the AEGIS
// SOC pipeline into a concise markdown incident report. The LLM is the logic;
// it uses no tools and must rely only on the facts in the input.
import { llmAgent } from "@guildai/agents-sdk";
import { z } from "zod";

const inputSchema = z.object({
  entity: z.string().describe("Primary affected entity (host, account or service)"),
  source_ips: z.array(z.string()).describe("Attacker / suspicious source IPs"),
  compromised_users: z.array(z.string()).describe("User accounts judged compromised"),
  stages: z
    .array(z.object({ stage: z.string(), evidence: z.string().default("") }))
    .describe("Observed kill-chain stages in order, each with supporting evidence"),
  rules_applied: z.array(z.string()).describe("Defensive rules the system applied, e.g. 'block_ip 203.0.113.7'"),
  seconds_to_rules: z
    .number()
    .nullable()
    .describe("Seconds from first detection to rules being applied"),
});

const systemPrompt: string = `
You are AEGIS Incident Analyst, a SOC analyst that writes concise incident reports.

The user message is an incident summary with these fields:
entity, source_ips, compromised_users, stages, rules_applied, seconds_to_rules.

Write a markdown report with exactly these sections:

# Incident Report: <entity>
## Summary
2-4 sentences: what happened, to which entity, from which source IPs, which users
were compromised, and how quickly defensive rules were applied (seconds_to_rules).
## Kill-Chain Timeline
A numbered list of the stages in the order given. Include the evidence
given for each stage; do not invent times.
## Actions Taken
A bullet list of rules_applied, plus one line stating time-to-rules in seconds.
## Recommendations
3-5 short, concrete follow-ups that follow directly from the facts (e.g. reset
credentials of the listed compromised users, review activity from the listed IPs,
verify the applied rules). Do not reference systems, users or IPs not in the input.

Rules:
- Use ONLY facts present in the input. Never invent IPs, users, hostnames, times,
  malware names, CVEs, attribution or impact.
- If a field is empty or null, say "None recorded" rather than guessing.
- Be concise: aim for under 300 words. Output only the markdown report.
`;

export default llmAgent({
  description:
    "Writes a concise SOC incident report (summary, kill-chain timeline, actions, recommendations) from an AEGIS JSON incident summary, using only the facts provided.",
  inputSchema,
  inputTemplate: `Incident summary (JSON values):
- entity: {{entity}}
- source_ips: {{source_ips}}
- compromised_users: {{compromised_users}}
- stages: {{stages}}
- rules_applied: {{rules_applied}}
- seconds_to_rules: {{seconds_to_rules}}`,
  tools: {},
  systemPrompt,
  mode: "one-shot",
  useWorkspaceAgents: false,
});
