import { useEffect, useRef, useState } from "react";
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

export default function DocumentVault() {
  const fileInputRef = useRef(null);
  const token = localStorage.getItem("token");
  const [files, setFiles] = useState([]);
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

  const clearVaultSession = () => {
    sessionStorage.removeItem(VAULT_PIN_SESSION_KEY);
    setVaultPin("");
    setVaultUnlocked(false);
    setFiles([]);
  };

  const loadDocuments = async (pinOverride = vaultPin) => {
    if (!token) return;

    try {
      const res = await fetch("http://localhost:5000/api/profile/documents", {
        headers: buildVaultHeaders(pinOverride),
      });
      const data = await res.json();

      if (!res.ok) {
        setStatus({ type: "error", message: data.message || "Failed to load documents." });
        if (res.status === 423 || res.status === 403) {
          clearVaultSession();
        }
        return;
      }

      setFiles(data.documents || []);
      setVaultUnlocked(true);
      setStatus({ type: "", message: "" });
    } catch {
      setStatus({ type: "error", message: "Failed to load documents." });
    }
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
          await loadDocuments(vaultPin);
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
      const res = await fetch("http://localhost:5000/api/profile/documents/vault-unlock", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ pin: vaultPin.trim() }),
      });
      const data = await res.json();

      if (!res.ok) {
        clearVaultSession();
        setStatus({ type: "error", message: data.message || "Could not unlock document vault." });
        return;
      }

      sessionStorage.setItem(VAULT_PIN_SESSION_KEY, vaultPin.trim());
      setVaultUnlocked(true);
      setStatus({ type: "success", message: "Document vault unlocked." });
      await loadDocuments(vaultPin.trim());
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
      sessionStorage.setItem(VAULT_PIN_SESSION_KEY, newVaultPin.trim());
      setVaultUnlocked(true);
      setStatus({ type: "success", message: data.message || "Document vault PIN saved." });
      await loadDocuments(newVaultPin.trim());
    } catch {
      setStatus({ type: "error", message: "Could not save document vault PIN." });
    }
  };

  const handleLockVault = () => {
    setVaultPin("");
    clearVaultSession();
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
          clearVaultSession();
        }
        setStatus({ type: "error", message: data.message || "Could not save documents." });
        return;
      }

      setFiles(data.documents || []);
      setStatus({ type: "success", message: "Documents saved in vault." });
    } catch {
      setStatus({ type: "error", message: "Could not save documents." });
    }
  };

  const handleDelete = async (docId) => {
    if (!token) return;

    try {
      const res = await fetch(`http://localhost:5000/api/profile/documents/${docId}`, {
        method: "DELETE",
        headers: buildVaultHeaders(),
      });
      const data = await res.json();

      if (!res.ok) {
        if (res.status === 403 || res.status === 423) {
          clearVaultSession();
        }
        setStatus({ type: "error", message: data.message || "Could not delete document." });
        return;
      }

      setFiles((prev) => prev.filter((doc) => doc.id !== docId));
      setStatus({ type: "success", message: "Document deleted." });
    } catch {
      setStatus({ type: "error", message: "Could not delete document." });
    }
  };

  const handleOpenDocument = async (file) => {
    if (!token || !file?.download_url) return;

    try {
      const res = await fetch(`http://localhost:5000${file.download_url}`, {
        headers: buildVaultHeaders(),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        if (res.status === 403 || res.status === 423) {
          clearVaultSession();
        }
        setStatus({ type: "error", message: data.message || "Could not open document." });
        return;
      }

      const blob = await res.blob();
      const objectUrl = window.URL.createObjectURL(blob);
      window.open(objectUrl, "_blank", "noopener,noreferrer");
      window.setTimeout(() => window.URL.revokeObjectURL(objectUrl), 60_000);
    } catch {
      setStatus({ type: "error", message: "Could not open document." });
    }
  };

  return (
    <>
      <Navbar />
      <main className="profile-page">
        <section className="profile-hero">
          <div className="profile-hero__card">
            <h1>Document Vault</h1>
            <p>Unlock your private vault, upload important files, and manage them safely from the main website.</p>
          </div>
        </section>

        <section className="profile-shell document-vault-shell">
          <div className="document-vault-layout">
            <aside className="document-vault-sidebar">
              <div className="document-vault-panel">
                <span className="document-vault-panel__kicker">Vault status</span>
                <h2>{vaultUnlocked ? "Unlocked and ready" : hasVaultPin ? "Protected by your PIN" : "Set up your secure vault"}</h2>
                <p>
                  {vaultUnlocked
                    ? "Open files, upload new documents, change your PIN, or remove files you no longer need."
                    : hasVaultPin
                      ? "Enter your vault PIN to view and manage documents stored safely in your account."
                      : "Create a 4 to 8 digit PIN first. This PIN protects all future access to your document vault."}
                </p>

                {!vaultLoading && !vaultUnlocked && (
                  <div className="document-vault-panel__form">
                    <div className="review-card">
                      <h4>{hasVaultPin ? "Unlock document vault" : "Create document vault PIN"}</h4>

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
                  </div>
                )}

                {vaultUnlocked && (
                  <>
                    <div className="document-vault-status-grid">
                      <div className="document-vault-status-card">
                        <span>Protection</span>
                        <strong>{hasVaultPin ? "PIN enabled" : "No PIN"}</strong>
                      </div>
                      <div className="document-vault-status-card">
                        <span>Documents</span>
                        <strong>{files.length}</strong>
                      </div>
                    </div>

                    <div className="document-vault-panel__actions">
                      <button type="button" className="profile-btn profile-btn--ghost" onClick={handleLockVault}>
                        Lock Vault
                      </button>
                      <button type="button" className="profile-btn profile-next-btn" onClick={() => setStatus({ type: "", message: "" })}>
                        Vault Unlocked
                      </button>
                    </div>

                    {hasVaultPin && (
                      <div className="review-card">
                        <h4>Change vault PIN</h4>
                        <form onSubmit={handleSetVaultPin} className="settings-form">
                          <label htmlFor="current-vault-pin">Current PIN</label>
                          <input
                            id="current-vault-pin"
                            type="password"
                            inputMode="numeric"
                            placeholder="Current PIN"
                            value={currentVaultPin}
                            onChange={(event) => setCurrentVaultPin(event.target.value)}
                          />

                          <label htmlFor="reset-vault-pin">New PIN</label>
                          <input
                            id="reset-vault-pin"
                            type="password"
                            inputMode="numeric"
                            placeholder="4 to 8 digit PIN"
                            value={newVaultPin}
                            onChange={(event) => setNewVaultPin(event.target.value)}
                          />

                          <label htmlFor="reset-vault-pin-confirm">Confirm New PIN</label>
                          <input
                            id="reset-vault-pin-confirm"
                            type="password"
                            inputMode="numeric"
                            placeholder="Confirm new PIN"
                            value={confirmNewVaultPin}
                            onChange={(event) => setConfirmNewVaultPin(event.target.value)}
                          />

                          <button type="submit">Update Vault PIN</button>
                        </form>
                      </div>
                    )}
                  </>
                )}
              </div>
            </aside>

            <div className="document-vault-main">
              <div className="document-vault-main__head">
                <div>
                  <div className="document-vault-main__status-row">
                    <span className="document-vault-main__kicker">Private files</span>
                    <span className={`document-vault-state-chip ${vaultUnlocked ? "document-vault-state-chip--open" : "document-vault-state-chip--locked"}`}>
                      {vaultUnlocked ? "Vault unlocked" : "Vault locked"}
                    </span>
                  </div>
                  <h2>Your stored documents</h2>
                  <p>Keep IELTS reports, transcripts, certificates, and other admission documents in one secure place.</p>
                </div>
              </div>

              {vaultLoading ? (
                <div className="review-card">
                  <p className="profile-helper">Loading document vault...</p>
                </div>
              ) : !vaultUnlocked ? (
                <div className="document-vault-empty">
                  <h3>Unlock the vault to manage your files</h3>
                  <p>Once your PIN is verified, you can upload documents, open them, and remove them from the vault.</p>
                </div>
              ) : (
                <>
                  <div className="document-vault-upload-grid">
                    <div className="document-vault-uploader">
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

                      <div className="upload-card document-vault-upload-card">
                        <div className="upload-icon">
                          <div className="upload-icon__sheet"></div>
                        </div>
                        <p className="upload-title">Upload to your vault</p>
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
                    </div>

                    <div className="document-vault-summary-card">
                      <span className="document-vault-summary-card__kicker">What belongs here</span>
                      <ul>
                        <li>IELTS, TOEFL, SAT, and academic score reports</li>
                        <li>School leaving certificates, transcripts, and marksheets</li>
                        <li>Passport copies, financial documents, and visa files</li>
                      </ul>
                      <div className="document-vault-summary-card__policy">
                        <strong>Allowed files</strong>
                        <p>PDF, DOC, DOCX, JPG, PNG, and WEBP only. Maximum 10 MB per file.</p>
                      </div>
                    </div>
                  </div>

                  {files.length === 0 ? (
                    <div className="document-vault-empty">
                      <h3>No documents in the vault yet</h3>
                      <p>Upload your first file from the panel above and it will appear here for future access.</p>
                    </div>
                  ) : (
                    <div className="file-list document-vault-file-list">
                      {files.map((file) => (
                        <div className="file-row document-vault-file-row" key={file.id}>
                          <div className="file-meta">
                            <span className="file-icon"></span>
                            <div>
                              <h5>{file.file_name}</h5>
                              <p>{file.file_size}</p>
                              <p className="file-review-status">Type: {file.document_type || "other"}</p>
                              <p className="file-review-status">
                                Review: {file.review_status || "pending"}
                                {file.review_comment ? ` - ${file.review_comment}` : ""}
                              </p>
                            </div>
                          </div>
                          <div className="file-actions">
                            <button
                              type="button"
                              className="file-btn"
                              onClick={() => handleOpenDocument(file)}
                            >
                              Open
                            </button>
                            <button
                              type="button"
                              className="file-btn file-btn--danger"
                              onClick={() => handleDelete(file.id)}
                            >
                              Delete
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}

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
