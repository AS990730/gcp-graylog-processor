import os
import json
import requests
import vertexai
from vertexai.generative_models import GenerativeModel
from flask import Flask, request, jsonify

# --- CONFIGURATION ---
# You will get this URL from the Graylog Input you create in Step 4.
# It will look something like: "http://<your-graylog-ip>:12201/gelf"
GELF_HTTP_INPUT_URL = "YOUR_GRAYLOG_GELF_HTTP_INPUT_URL"
# -------------------

# Initialize Flask App
app = Flask(__name__)

# Initialize Vertex AI client
vertexai.init()
model = GenerativeModel("gemini-1.5-pro-001")

@app.route("/", methods=["POST"])
def handler():
    """
    Receives a full Graylog message object, gets an AI analysis,
    and sends the result back to a new Graylog GELF HTTP Input.
    """
    original_message = request.get_json(silent=True)

    if not original_message:
        return "OK", 200 # Acknowledge the request even if body is empty

    # We now have the original message sent by the Graylog Output
    alert_data = json.dumps(original_message.get('message', {}))

    prompt = f"""
    You are a Tier 2 SOC Analyst. Analyze the following security alert JSON.
    The alert data is: ```json\n{alert_data}\n```

    Your tasks:
    1. Briefly summarize the event in one sentence.
    2. Based on the rule description, what is the MITRE ATT&CK Tactic and Technique?
    3. Rate the likely severity on a scale of 1-10.
    4. Is this likely a false positive? Answer with 'Yes', 'No', or 'Needs Investigation'.
    5. Suggest one immediate investigation step.

    Respond ONLY in a structured JSON format.
    """

    try:
        # 1. Get the AI analysis
        response = model.generate_content(prompt)
        cleaned_response = response.text.strip().replace("`", "").replace("json", "")
        ai_data = json.loads(cleaned_response)

        # 2. Prepare a NEW log message (GELF format) with the AI results
        gelf_message = {
            "version": "1.1",
            "host": original_message.get('source', 'unknown_host'),
            "short_message": ai_data.get('llm_summary', 'AI Analysis Complete'),
            "_original_message": original_message.get('message', {}).get('message'),
            "_llm_summary": ai_data.get('llm_summary'),
            "_llm_mitre_tactic": ai_data.get('llm_mitre_tactic'),
            "_llm_mitre_technique": ai_data.get('llm_mitre_technique'),
            "_llm_severity": ai_data.get('llm_severity'),
            "_llm_is_false_positive": ai_data.get('llm_is_false_positive'),
            "_llm_next_step": ai_data.get('llm_next_step'),
            "_event_source": "VertexAI_Enrichment"
        }

        # 3. Send the new log back to Graylog
        if GELF_HTTP_INPUT_URL != "YOUR_GRAYLOG_GELF_HTTP_INPUT_URL":
            requests.post(GELF_HTTP_INPUT_URL, json=gelf_message, timeout=5)

        # 4. Return a success response to the original Graylog Output
        return "OK", 200

    except Exception as e:
        print(f"An error occurred: {e}")
        # Still return OK so the Graylog Output doesn't get clogged
        return "OK", 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
