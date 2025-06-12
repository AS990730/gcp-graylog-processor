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
    Receives a plain text log message from Graylog, analyzes it with Vertex AI,
    and returns a structured JSON response.
    """
    # Get the raw log message text sent from Graylog
    log_message = request.get_data(as_text=True)

    if not log_message:
        return jsonify({"error": "Invalid request. No log message text found."}), 400

    # --- This is the simplified prompt ---
    prompt = f"""
    You are a Tier 2 SOC Analyst. Analyze the following raw security log message.
    The log message is: ```{log_message}```

    Your tasks:
    1. Briefly summarize the event in one sentence.
    2. Based on the log, what is the likely MITRE ATT&CK Tactic and Technique? If not applicable, state "N/A".
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
