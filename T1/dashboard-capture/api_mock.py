from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/api/traffic/aggregate", methods=["POST"])
def aggregate():
    data = request.json
    print("=== Recebi janela ===")
    print(data)
    return jsonify({"status": "ok"}), 201

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)