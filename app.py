import os
import uuid
import json
from flask import Flask, request, render_template, jsonify
import librosa
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
import joblib
from security import derive_key_from_passphrase, decrypt_bytes_aes_gcm, sha256_bytes

app = Flask(__name__)

def extract_mfcc_features(audio_path, n_mfcc=13, n_fft=2048, hop_length=512):
    try:
        audio_data, sr = librosa.load(audio_path, sr=None)
    except Exception as e:
        print(f"Error loading audio file {audio_path}: {e}")
        return None

    mfccs = librosa.feature.mfcc(y=audio_data, sr=sr, n_mfcc=n_mfcc, n_fft=n_fft, hop_length=hop_length)
    return np.mean(mfccs.T, axis=0)

def ensure_models():
    model_filename = "svm_model.pkl"
    scaler_filename = "scaler.pkl"
    if not os.path.exists(model_filename) or not os.path.exists(scaler_filename):
        from main import create_dataset, train_model
        X_genuine, y_genuine = create_dataset("real_audio", label=0)
        X_deepfake, y_deepfake = create_dataset("deepfake_audio", label=1)
        if len(X_genuine) == 0 or len(X_deepfake) == 0:
            raise RuntimeError("Training data not found in real_audio or deepfake_audio")
        import numpy as np
        X = np.vstack((X_genuine, X_deepfake))
        y = np.hstack((y_genuine, y_deepfake))
        train_model(X, y)

def analyze_audio(input_audio_path):
    model_filename = "svm_model.pkl"
    scaler_filename = "scaler.pkl"
    try:
        ensure_models()
    except Exception as e:
        return "Error: Unable to prepare model: " + str(e)

    if not os.path.exists(input_audio_path):
        return "Error: The specified file does not exist."
    elif not input_audio_path.lower().endswith(".wav"):
        return "Error: The specified file is not a .wav file."

    mfcc_features = extract_mfcc_features(input_audio_path)
    if mfcc_features is not None:
        try:
            scaler = joblib.load(scaler_filename)
        except Exception as e:
            return "Error: Unable to load scaler: " + str(e)
        mfcc_features_scaled = scaler.transform(mfcc_features.reshape(1, -1))
        try:
            svm_classifier = joblib.load(model_filename)
        except Exception as e:
            return "Error: Unable to load model: " + str(e)
        prediction = svm_classifier.predict(mfcc_features_scaled)

        if prediction[0] == 0:
            return "The input audio is classified as genuine."
        else:
            return "The input audio is classified as deepfake."
    else:
        return "Error: Unable to process the input audio."

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        if "audio_file" not in request.files:
            return render_template("index.html", message="No file part")
        
        audio_file = request.files["audio_file"]
        if audio_file.filename == "":
            return render_template("index.html", message="No selected file")
        
        if audio_file and allowed_file(audio_file.filename):
            if not os.path.exists("uploads"):
                os.makedirs("uploads")
                
            audio_path = os.path.join("uploads", audio_file.filename)
            audio_file.save(audio_path)
            try:
                result = analyze_audio(audio_path)
                return render_template("result.html", result=result)
            finally:
                try:
                    if os.path.exists(audio_path):
                        os.remove(audio_path)
                except Exception:
                    pass
        
        return render_template("index.html", message="Invalid file format. Only .wav files allowed.")
    
    return render_template("index.html")

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() == "wav"

@app.route("/secure_upload", methods=["POST"])
def secure_upload():
    data = request.get_json(force=True)
    ciphertext_b64 = data.get("ciphertext_b64")
    nonce_b64 = data.get("nonce_b64")
    tag_b64 = data.get("tag_b64")
    sha256_sent = data.get("sha256")
    passphrase = os.environ.get("AES_PASSPHRASE", "change-this-passphrase")
    key = derive_key_from_passphrase(passphrase)
    try:
        plaintext = decrypt_bytes_aes_gcm(ciphertext_b64, nonce_b64, tag_b64, key)
    except Exception:
        return jsonify({"error": "decryption_failed"}), 400
    sha256_recv = sha256_bytes(plaintext)
    hash_match = sha256_recv == sha256_sent
    tmp_dir = "uploads"
    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)
    tmp_path = os.path.join(tmp_dir, f"{uuid.uuid4().hex}.wav")
    with open(tmp_path, "wb") as f:
        f.write(plaintext)
    result = analyze_audio(tmp_path)
    os.remove(tmp_path)
    return jsonify({"hash_match": hash_match, "result": result})

if __name__ == "__main__":
    try:
        ensure_models()
    except Exception:
        pass
    use_ssl = os.environ.get("USE_SSL", "1")
    if use_ssl == "0":
        app.run(debug=True)
    else:
        cert_file = "cert.pem"
        key_file = "key.pem"
        ssl_ctx = (cert_file, key_file) if os.path.exists(cert_file) and os.path.exists(key_file) else "adhoc"
        app.run(debug=True, ssl_context=ssl_ctx)
