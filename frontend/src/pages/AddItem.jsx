import { useState, useRef, useCallback, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { encryptPayload, storeVaultEntry } from '../utils/vaultCrypto'
import { auditSecret } from '../utils/auditApi'
import { getMasterKey } from '../utils/sessionSecrets'
import AuditBadge from '../components/AuditBadge'
import Sidebar from '../components/Sidebar'
import StatusBar from '../components/StatusBar'
import './AddItem.css'

const CATEGORIES = ['Email', 'Cloud', 'Finance', 'Media', 'Social', 'Dev', 'Other']

export default function AddItem() {
  const navigate = useNavigate()
  const masterPassword = getMasterKey()
  const debounceRef = useRef(null)

  // Form state
  const [label, setLabel] = useState('')
  const [username, setUsername] = useState('')
  const [secret, setSecret] = useState('')
  const [url, setUrl] = useState('')
  const [category, setCategory] = useState('Other')
  const [notes, setNotes] = useState('')

  // Audit state
  const [auditResult, setAuditResult] = useState(null)
  const [auditLoading, setAuditLoading] = useState(false)

  // Submit state
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  // Redirect if not logged in
  useEffect(() => {
    if (!sessionStorage.getItem('sv_access_token')) {
      navigate('/')
    }
  }, [])

  // ═══ Audit Logic ═══

  const runAudit = useCallback(async (value) => {
    if (!value || value.trim().length < 2) {
      setAuditResult(null)
      return
    }
    setAuditLoading(true)
    try {
      const result = await auditSecret(value)
      setAuditResult(result)
    } catch {
      setAuditResult(null)
    } finally {
      setAuditLoading(false)
    }
  }, [])

  // Auto-audit: debounced on every change (800ms)
  const handleSecretChange = (e) => {
    const val = e.target.value
    setSecret(val)

    // Clear previous debounce
    if (debounceRef.current) clearTimeout(debounceRef.current)

    // Debounce auto-audit
    debounceRef.current = setTimeout(() => {
      runAudit(val)
    }, 800)
  }

  // Auto-audit on paste (immediate)
  const handlePaste = (e) => {
    // The onChange will fire too, so we do an immediate audit
    setTimeout(() => {
      const val = e.target.value
      if (debounceRef.current) clearTimeout(debounceRef.current)
      runAudit(val)
    }, 50)
  }

  // Manual audit button
  const handleManualAudit = () => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    runAudit(secret)
  }

  // ═══ Submit Logic ═══

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!label.trim() || !secret.trim()) {
      setError('Label and Secret are required.')
      return
    }

    setSaving(true)
    setError('')

    try {
      const payload = {
        username: username.trim(),
        password: secret,
        url: url.trim(),
        category,
        notes: notes.trim(),
      }

      const { ciphertext, iv, salt } = await encryptPayload(payload, masterPassword)
      await storeVaultEntry(label.trim(), ciphertext, iv, salt)

      navigate('/vault')
    } catch (err) {
      setError('Failed to store: ' + err.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="app-layout">
      <Sidebar />
      <main className="main-content add-page animate-in">
        {/* Back nav */}
        <button className="add__back btn-ghost" onClick={() => navigate('/vault')}>
          <span className="icon icon-sm">arrow_back</span>
          Back to Vault
        </button>

        <div className="add__layout">
          {/* Left: Form */}
          <form className="add__form" onSubmit={handleSubmit}>
            <div className="add__form-header">
              <span className="icon text-green">add_circle</span>
              <span className="add__form-title">Add New Credential</span>
            </div>

            {error && (
              <div className="add__error">
                <span className="icon icon-sm">error</span>
                {error}
              </div>
            )}

            {/* Label */}
            <div className="input-group">
              <label htmlFor="add-label">Label *</label>
              <input
                id="add-label"
                type="text"
                className="input-field"
                placeholder="e.g. Gmail, AWS Prod, GitHub..."
                value={label}
                onChange={e => setLabel(e.target.value)}
              />
            </div>

            {/* Username */}
            <div className="input-group">
              <label htmlFor="add-username">Username / Email</label>
              <input
                id="add-username"
                type="text"
                className="input-field"
                placeholder="user@example.com"
                value={username}
                onChange={e => setUsername(e.target.value)}
              />
            </div>

            {/* Secret / Password — audited field */}
            <div className="input-group">
              <label htmlFor="add-secret">
                Password / Secret / API Key *
                <span className="add__audit-hint">
                  <span className="icon icon-sm">auto_fix_high</span>
                  Auto-audited
                </span>
              </label>
              <div className="add__secret-wrap">
                <textarea
                  id="add-secret"
                  className="input-field add__secret-input"
                  placeholder="Paste or type your secret here..."
                  value={secret}
                  onChange={handleSecretChange}
                  onPaste={handlePaste}
                  rows={3}
                />
                <button
                  type="button"
                  className="add__audit-btn"
                  onClick={handleManualAudit}
                  disabled={!secret.trim() || auditLoading}
                  title="Run manual audit"
                >
                  <span className="icon icon-sm">
                    {auditLoading ? 'sync' : 'policy'}
                  </span>
                  Audit
                </button>
              </div>

              {/* Audit badge */}
              <AuditBadge auditResult={auditResult} loading={auditLoading} />
            </div>

            {/* URL */}
            <div className="input-group">
              <label htmlFor="add-url">Service URL</label>
              <input
                id="add-url"
                type="text"
                className="input-field"
                placeholder="https://..."
                value={url}
                onChange={e => setUrl(e.target.value)}
              />
            </div>

            {/* Category */}
            <div className="input-group">
              <label>Category</label>
              <div className="add__categories">
                {CATEGORIES.map(cat => (
                  <button
                    key={cat}
                    type="button"
                    className={`add__cat-btn ${category === cat ? 'add__cat-btn--active' : ''}`}
                    onClick={() => setCategory(cat)}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            </div>

            {/* Notes */}
            <div className="input-group">
              <label htmlFor="add-notes">Notes</label>
              <textarea
                id="add-notes"
                className="input-field"
                placeholder="Optional notes..."
                value={notes}
                onChange={e => setNotes(e.target.value)}
                rows={2}
              />
            </div>

            {/* Submit */}
            <button
              type="submit"
              className="btn btn-primary add__submit"
              disabled={saving || !label.trim() || !secret.trim()}
            >
              {saving ? (
                <>
                  <span className="icon icon-sm" style={{ animation: 'spin 1s linear infinite' }}>sync</span>
                  Encrypting & Storing...
                </>
              ) : (
                <>
                  <span className="icon icon-sm">lock</span>
                  Encrypt & Store
                </>
              )}
            </button>
          </form>

          {/* Right: Info panel */}
          <div className="add__info">
            <div className="card">
              <h4 className="add__info-title">
                <span className="icon icon-sm">security</span>
                Zero-Knowledge Pipeline
              </h4>
              <div className="add__info-steps">
                <div className="add__step">
                  <span className="add__step-num">01</span>
                  <div>
                    <strong>Paste & Audit</strong>
                    <p className="text-muted">Secret is analyzed ephemerally by Django — never saved.</p>
                  </div>
                </div>
                <div className="add__step">
                  <span className="add__step-num">02</span>
                  <div>
                    <strong>Client-Side Encryption</strong>
                    <p className="text-muted">AES-256-GCM with your master password via PBKDF2.</p>
                  </div>
                </div>
                <div className="add__step">
                  <span className="add__step-num">03</span>
                  <div>
                    <strong>Dumb Storage</strong>
                    <p className="text-muted">Only ciphertext hits the server. Plaintext never leaves your browser.</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <StatusBar />
      </main>
    </div>
  )
}
