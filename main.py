import os
import json
import vertexai
from vertexai.generative_models import GenerativeModel
from flask import Flask, request, jsonify

# Initialize Flask App
app = Flask(__name__)

# Initialize Vertex AI client
vertexai.init()
model = GenerativeModel("gemini-1.5-pro-001")

@app.route("/", methods=["POST"])
def handler():
    """
    Receives an alert from Graylog, analyzes it with Vertex AI,
    and returns a structured JSON response.
    """
    request_json = request.get_json(silent=True)

    if not request_json or 'message' not in request_json:
        return jsonify({"error": "Invalid request. No 'message' field found."}), 400

    alert_data = json.dumps(request_json.get('message', {}))
    
    prompt = f"""
    You are a Tier 2 SOC Analyst. Analyze the following security alert JSON.
    The alert data is: ```json\n{alert_data}\n```

    Your tasks:
    1. Briefly summarize the event in one sentence.
    2. Based on the rule description and log data, what is the MITRE ATT&CK Tactic and Technique? If not applicable, state "N/A".
    3. Rate the likely severity on a scale of 1-10.
    4. Is this likely a false positive? Answer with 'Yes', 'No', or 'Needs Investigation'.
    5. Suggest one immediate investigation step for an analyst.

    Respond ONLY in a structured JSON format. Do not include any other text or markdown formatting.
    """

    try:
        response = model.generate_content(prompt)
        cleaned_response = response.text.strip().replace("`", "").replace("json", "")
        parsed_json = json.loads(cleaned_response)
        return jsonify(parsed_json), 200
    except Exception as e:
        error_message = f"Error processing request or calling Vertex AI: {e}"
        print(error_message)
        return jsonify({"error": error_message}), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
