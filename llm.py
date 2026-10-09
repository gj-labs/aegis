"""AkashML client (OpenAI-compatible). Every call is logged to agent_log so the dashboard can show model, latency and tokens."""
import json, os, re, time
from dotenv import load_dotenv

load_dotenv()
BASE_URL = os.environ.get("AKASH_BASE_URL") or "https://api.akashml.com/v1"
MODEL = os.environ.get("AKASH_MODEL") or "meta-llama/Llama-3.3-70B-Instruct"


def parse_json(text):
    text = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip()
    a, b = text.find("{"), text.rfind("}")
    if a < 0 or b < a:
        raise ValueError("no JSON object in model output")
    return json.loads(text[a:b + 1])


class Akash:
    def __init__(self, log):
        from openai import OpenAI
        self.log = log                      # log(agent, incident_id, message, model, latency_ms, tin, tout)
        self.client = OpenAI(api_key=os.environ["AKASH_API_KEY"], base_url=BASE_URL, timeout=30)

    def call(self, agent, incident_id, system, user, max_tokens=900):
        """Returns a dict, or None if the model could not produce valid JSON (caller falls back, and says so)."""
        msgs = [{"role": "system", "content": system + " Respond with a single JSON object and nothing else."},
                {"role": "user", "content": user}]
        for attempt in range(2):
            t0 = time.perf_counter()
            try:
                try:
                    r = self.client.chat.completions.create(model=MODEL, messages=msgs, temperature=0.1,
                                                            max_tokens=max_tokens,
                                                            response_format={"type": "json_object"})
                except Exception:
                    r = self.client.chat.completions.create(model=MODEL, messages=msgs, temperature=0.1,
                                                            max_tokens=max_tokens)
                ms = int((time.perf_counter() - t0) * 1000)
                u = r.usage
                out = parse_json(r.choices[0].message.content or "")
                self.log(agent, incident_id, "akash inference ok", MODEL, ms,
                         getattr(u, "prompt_tokens", 0), getattr(u, "completion_tokens", 0))
                return out
            except Exception as e:
                ms = int((time.perf_counter() - t0) * 1000)
                self.log(agent, incident_id, f"akash call failed (attempt {attempt+1}): {str(e)[:120]}", MODEL, ms, 0, 0)
                msgs.append({"role": "user", "content": "Return ONLY valid JSON matching the requested shape."})
        return None
