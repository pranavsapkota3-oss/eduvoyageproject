import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";

const documentTypeOptions = [
  { value: "passport", label: "Passport" },
  { value: "transcript", label: "Transcript" },
  { value: "school_leaving_certificate", label: "School Leaving Certificate" },
  { value: "marksheet", label: "Marksheet" },
  { value: "character_certificate", label: "Character Certificate" },
  { value: "ielts", label: "IELTS" },
  { value: "toefl", label: "TOEFL" },
  { value: "sat", label: "SAT" },
  { value: "financial", label: "Financial Document" },
  { value: "visa", label: "Visa" },
  { value: "resume", label: "Resume / CV" },
  { value: "recommendation", label: "Recommendation Letter" },
  { value: "sop", label: "Statement of Purpose" },
  { value: "lor", label: "Letter of Recommendation" },
  { value: "custom", label: "Custom document" },
];

const VAULT_PIN_SESSION_KEY = "document_vault_session_pin_v1";
const MAX_DOCUMENT_SIZE_BYTES = 10 * 1024 * 1024;
const ACCEPTED_DOCUMENT_EXTENSIONS = ".pdf,.doc,.docx,.jpg,.jpeg,.png,.webp";

function validateSelectedFiles(selectedFiles) {
  const unsupported = selectedFiles.find((file) => !/\.(pdf|doc|docx|jpg|jpeg|png|webp)$/i.test(file.name || ""));
  if (unsupported) {
    return "Only PDF, DOC, DOCX, JPG, PNG, and WEBP files are allowed.";
  }

  const oversized = selectedFiles.find((file) => Number(file.size || 0) > MAX_DOCUMENT_SIZE_BYTES);
  if (oversized) {
    return "Each file must be 10 MB or smaller.";
  }

  return "";
}

export default function Documents() {
  const fileInputRef = useRef(null);
  const token = localStorage.getItem("token");
  const [documentType, setDocumentType] = useState("passport");
  const [customDocumentType, setCustomDocumentType] = useState("");
  const [status, setStatus] = useState({ type: "", message: "" });
  const [vaultLoading, setVaultLoading] = useState(true);
  const [vaultUnlocked, setVaultUnlocked] = useState(false);
  const [hasVaultPin, setHasVaultPin] = useState(false);
  const [vaultPin, setVaultPin] = useState(() => sessionStorage.getItem(VAULT_PIN_SESSION_KEY) || "");
  const [newVaultPin, setNewVaultPin] = useState("");
  const [confirmNewVaultPin, setConfirmNewVaultPin] = useState("");
  const [currentVaultPin, setCurrentVaultPin] = useState("");

  const buildVaultHeaders = (pinOverride = vaultPin) => {
    const headers = { Authorization: `Bearer ${token}` };
    if (pinOverride) {
      headers["x-vault-pin"] = pinOverride;
    }
    return headers;
  };

  const unlockVaultWithPin = async (pinValue) => {
    const normalizedPin = String(pinValue || "").trim();
    const res = await fetch("http://localhost:5000/api/profile/documents/vault-unlock", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ pin: normalizedPin }),
    });
    const data = await res.json();

    if (!res.ok) {
      sessionStorage.removeItem(VAULT_PIN_SESSION_KEY);
      setVaultPin("");
      setVaultUnlocked(false);
      setStatus({ type: "error", message: data.message || "Could not unlock document vault." });
      return false;
    }

    sessionStorage.setItem(VAULT_PIN_SESSION_KEY, normalizedPin);
    setVaultUnlocked(true);
    return true;
  };

  useEffect(() => {
    const loadVaultStatus = async () => {
      if (!token) {
        setVaultLoading(false);
        return;
      }

      try {
        const res = await fetch("http://localhost:5000/api/profile/documents/vault-status", {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = await res.json();
        if (!res.ok) {
          setStatus({ type: "error", message: data.message || "Failed to load document vault." });
          return;
        }

        const pinExists = !!data.has_pin;
        setHasVaultPin(pinExists);

        if (pinExists && vaultPin) {
          await unlockVaultWithPin(vaultPin);
        } else {
          setVaultUnlocked(false);
        }
      } catch {
        setStatus({ type: "error", message: "Failed to load document vault." });
      } finally {
        setVaultLoading(false);
      }
    };

    loadVaultStatus();
  }, []);

  const handleUnlockVault = async (event) => {
    event.preventDefault();
    if (!token) {
      setStatus({ type: "error", message: "Please login again." });
      return;
    }

    if (!vaultPin.trim()) {
      setStatus({ type: "error", message: "Enter your document vault PIN." });
      return;
    }

    try {
      const unlocked = await unlockVaultWithPin(vaultPin.trim());
      if (!unlocked) return;
      setStatus({ type: "success", message: "Vault unlocked. You can now add documents." });
    } catch {
      setStatus({ type: "error", message: "Could not unlock document vault." });
    }
  };

  const handleSetVaultPin = async (event) => {
    event.preventDefault();
    if (!token) {
      setStatus({ type: "error", message: "Please login again." });
      return;
    }

    if (!/^\d{4,8}$/.test(newVaultPin.trim())) {
      setStatus({ type: "error", message: "PIN must be 4 to 8 digits." });
      return;
    }

    if (newVaultPin.trim() !== confirmNewVaultPin.trim()) {
      setStatus({ type: "error", message: "PIN and confirm PIN do not match." });
      return;
    }

    try {
      const res = await fetch("http://localhost:5000/api/profile/documents/vault-pin", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          pin: newVaultPin.trim(),
          current_pin: currentVaultPin.trim(),
        }),
      });
      const data = await res.json();

      if (!res.ok) {
        setStatus({ type: "error", message: data.message || "Could not save document vault PIN." });
        return;
      }

      setHasVaultPin(true);
      setVaultPin(newVaultPin.trim());
      setCurrentVaultPin("");
      setNewVaultPin("");
      setConfirmNewVaultPin("");
      const savedPin = newVaultPin.trim();
      setVaultPin(savedPin);
      sessionStorage.setItem(VAULT_PIN_SESSION_KEY, savedPin);
      setVaultUnlocked(true);
      setStatus({ type: "success", message: data.message || "Document vault PIN saved. You can now add documents." });
    } catch {
      setStatus({ type: "error", message: "Could not save document vault PIN." });
    }
  };

  const handleLockVault = () => {
    sessionStorage.removeItem(VAULT_PIN_SESSION_KEY);
    setVaultPin("");
    setVaultUnlocked(false);
    setCurrentVaultPin("");
    setNewVaultPin("");
    setConfirmNewVaultPin("");
    setStatus({ type: "", message: "" });
  };

  const handleBrowse = () => {
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
      fileInputRef.current.click();
    }
  };

  const handleFileChange = async (event) => {
    if (!token) {
      setStatus({ type: "error", message: "Please login again." });
      return;
    }

    const selected = Array.from(event.target.files || []);
    if (selected.length === 0) return;
    if (documentType === "custom" && !customDocumentType.trim()) {
      setStatus({ type: "error", message: "Enter a custom document name first." });
      return;
    }

    const validationMessage = validateSelectedFiles(selected);
    if (validationMessage) {
      setStatus({ type: "error", message: validationMessage });
      return;
    }

    try {
      const formData = new FormData();
      formData.append("document_type", documentType);
      if (documentType === "custom") {
        formData.append("custom_document_type", customDocumentType);
      }
      selected.forEach((file) => formData.append("documents", file));

      const res = await fetch("http://localhost:5000/api/profile/documents", {
        method: "POST",
        headers: buildVaultHeaders(),
        body: formData,
      });
      const data = await res.json();

      if (!res.ok) {
        if (res.status === 403 || res.status === 423) {
          sessionStorage.removeItem(VAULT_PIN_SESSION_KEY);
          setVaultPin("");
          setVaultUnlocked(false);
        }
        setStatus({ type: "error", message: data.message || "Could not save documents." });
        return;
      }

      setStatus({ type: "success", message: "Documents saved in your document vault." });
    } catch {
      setStatus({ type: "error", message: "Could not save documents." });
    }
  };

  return (
    <>
      <Navbar />
      <main className="profile-page">
        <section className="profile-hero">
          <div className="profile-hero__card">
            <h1>Complete your Profile</h1>
            <p>Finish setting up your EduVoyage account to get personalized recommendations.</p>
          </div>
        </section>

        <section className="profile-shell">
          <div className="profile-layout">
            <aside className="profile-steps">
              <div className="profile-step">
                <span className="step-dot">1</span>
                <div>
                  <h4>Personal Information</h4>
                  <p>Basic details about you</p>
                </div>
              </div>
              <div className="profile-step">
                <span className="step-dot">2</span>
                <div>
                  <h4>Academic Background</h4>
                  <p>Your education history</p>
                </div>
              </div>
              <div className="profile-step">
                <span className="step-dot">3</span>
                <div>
                  <h4>Study Preferences</h4>
                  <p>Where and what you want</p>
                </div>
              </div>
              <div className="profile-step profile-step--active">
                <span className="step-dot">4</span>
                <div>
                  <h4>Documents</h4>
                  <p>Upload required files</p>
                </div>
              </div>
              <div className="profile-step">
                <span className="step-dot">5</span>
                <div>
                  <h4>Review &amp; Submit</h4>
                  <p>Finalize your profile</p>
                </div>
              </div>
            </aside>

            <div className="profile-form">
              <div className="profile-form__title">Add Documents</div>
              <p className="profile-helper">This profile step is only for adding files. Everything you upload here goes directly into your main document vault.</p>

              {vaultLoading ? (
                <p className="profile-helper">Loading document vault...</p>
              ) : (
                <>
                  {!vaultUnlocked && (
                    <div className="review-card">
                      <h4>{hasVaultPin ? "Unlock document vault" : "Create document vault PIN"}</h4>
                      <p className="profile-helper">
                        {hasVaultPin
                          ? "Enter your vault PIN first, then add documents from this profile step."
                          : "Set a 4 to 8 digit PIN first. This same PIN will protect your document vault on the main website."}
                      </p>

                      {hasVaultPin ? (
                        <form onSubmit={handleUnlockVault} className="settings-form">
                          <label htmlFor="vault-pin">Vault PIN</label>
                          <input
                            id="vault-pin"
                            type="password"
                            inputMode="numeric"
                            placeholder="Enter your PIN"
                            value={vaultPin}
                            onChange={(event) => setVaultPin(event.target.value)}
                          />
                          <button type="submit">Unlock Vault</button>
                        </form>
                      ) : (
                        <form onSubmit={handleSetVaultPin} className="settings-form">
                          <label htmlFor="new-vault-pin">New Vault PIN</label>
                          <input
                            id="new-vault-pin"
                            type="password"
                            inputMode="numeric"
                            placeholder="4 to 8 digit PIN"
                            value={newVaultPin}
                            onChange={(event) => setNewVaultPin(event.target.value)}
                          />

                          <label htmlFor="confirm-vault-pin">Confirm Vault PIN</label>
                          <input
                            id="confirm-vault-pin"
                            type="password"
                            inputMode="numeric"
                            placeholder="Re-enter PIN"
                            value={confirmNewVaultPin}
                            onChange={(event) => setConfirmNewVaultPin(event.target.value)}
                          />

                          <button type="submit">Create Vault PIN</button>
                        </form>
                      )}
                    </div>
                  )}

                  {vaultUnlocked && (
                    <>
                      <div className="profile-actions profile-actions--split">
                        <button type="button" className="profile-btn profile-btn--ghost" onClick={handleLockVault}>
                          Lock Vault
                        </button>
                        <Link to="/document-vault" className="profile-btn profile-next-btn">
                          Open Document Vault
                        </Link>
                      </div>

                      <div className="profile-field">
                        <label htmlFor="document-type">Document type</label>
                        <select
                          id="document-type"
                          value={documentType}
                          onChange={(event) => setDocumentType(event.target.value)}
                        >
                          {documentTypeOptions.map((option) => (
                            <option key={option.value} value={option.value}>
                              {option.label}
                            </option>
                          ))}
                        </select>
                      </div>

                      {documentType === "custom" && (
                        <div className="profile-field">
                          <label htmlFor="custom-document-type">Custom document name</label>
                          <input
                            id="custom-document-type"
                            type="text"
                            placeholder="Example: Migration certificate"
                            value={customDocumentType}
                            onChange={(event) => setCustomDocumentType(event.target.value)}
                          />
                        </div>
                      )}

                      <div className="upload-card">
                        <div className="upload-icon">
                          <div className="upload-icon__sheet"></div>
                        </div>
                        <p className="upload-title">Add documents to your vault</p>
                        <p className="upload-subtitle">PDF, DOC, DOCX, JPG, PNG, and WEBP up to 10 MB per file</p>
                        <button type="button" className="profile-btn profile-next-btn" onClick={handleBrowse}>
                          Browse Files
                        </button>
                        <input
                          ref={fileInputRef}
                          type="file"
                          accept={ACCEPTED_DOCUMENT_EXTENSIONS}
                          multiple
                          hidden
                          onChange={handleFileChange}
                        />
                      </div>
                    </>
                  )}
                </>
              )}

              <div className="profile-actions profile-actions--split">
                <Link to="/profile/preferences" className="profile-btn profile-btn--ghost">Back</Link>
                <Link to="/profile/review" className="profile-btn profile-next-btn">Next Submit</Link>
              </div>

              {status.message && (
                <p className={`profile-status profile-status--${status.type}`}>
                  {status.message}
                </p>
              )}
            </div>
          </div>
        </section>
      </main>
      <Footer />
    </>
  );
}
