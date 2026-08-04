import React, { useState, useEffect } from 'react';
import { Award, ShieldCheck, Download, Upload, RefreshCw, CheckCircle2, XCircle, Search, Lock, FileJson, X } from 'lucide-react';
import { WardenCertificate } from '@warden/shared';

interface CertificateManagerProps {
  onRefresh: () => void;
}

export const CertificateManager: React.FC<CertificateManagerProps> = ({ onRefresh }) => {
  const [certificates, setCertificates] = useState<WardenCertificate[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedCert, setSelectedCert] = useState<WardenCertificate | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [verifyHashInput, setVerifyHashInput] = useState('');
  const [verifyResult, setVerifyResult] = useState<any>(null);
  const [verifying, setVerifying] = useState(false);
  const [importModalOpen, setImportModalOpen] = useState(false);
  const [importJson, setImportJson] = useState('');
  const [importStatus, setImportStatus] = useState<string | null>(null);
  const [uploadTab, setUploadTab] = useState<'upload' | 'raw'>('upload');
  const [dragActive, setDragActive] = useState(false);
  const [selectedFileName, setSelectedFileName] = useState<string | null>(null);
  const [selectedFileSize, setSelectedFileSize] = useState<string | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);

  const processFileContent = (content: string, fileName: string, fileSize: number) => {
    try {
      JSON.parse(content);
      setImportJson(content);
      setSelectedFileName(fileName);
      setSelectedFileSize(`${(fileSize / 1024).toFixed(2)} KB`);
      setFileError(null);
    } catch (e) {
      setFileError('Invalid JSON content. Please select a valid Warden trust certificate JSON file.');
      setSelectedFileName(fileName);
      setSelectedFileSize(`${(fileSize / 1024).toFixed(2)} KB`);
      setImportJson('');
    }
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      if (file.type !== "application/json" && !file.name.endsWith('.json')) {
        setFileError('Only JSON certificate files are supported.');
        return;
      }
      const reader = new FileReader();
      reader.onload = (event) => {
        if (event.target?.result) {
          processFileContent(event.target.result as string, file.name, file.size);
        }
      };
      reader.readAsText(file);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      const reader = new FileReader();
      reader.onload = (event) => {
        if (event.target?.result) {
          processFileContent(event.target.result as string, file.name, file.size);
        }
      };
      reader.readAsText(file);
    }
  };

  const clearFile = () => {
    setSelectedFileName(null);
    setSelectedFileSize(null);
    setImportJson('');
    setFileError(null);
  };

  const fetchCertificates = async () => {
    setLoading(true);
    try {
      const res = await fetch(`/v1/registry/search?q=${encodeURIComponent(searchQuery)}`);
      const data = await res.json();
      const certs = Array.isArray(data) ? data : [];
      setCertificates(certs);
      if (certs.length > 0 && !selectedCert) {
        setSelectedCert(data[0]);
        setVerifyHashInput(data[0].tool.hash);
      }
    } catch (e) {
      console.error('Failed to fetch certificates:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCertificates();
  }, [searchQuery]);

  const handleSelectCert = (cert: WardenCertificate) => {
    setSelectedCert(cert);
    setVerifyHashInput(cert.tool.hash);
    setVerifyResult(null);
  };

  const handleVerifyHash = async () => {
    if (!selectedCert) return;
    setVerifying(true);
    setVerifyResult(null);
    try {
      const res = await fetch(`/v1/certificates/${selectedCert.certificate_id}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_hash: verifyHashInput }),
      });
      const data = await res.json();
      setVerifyResult(data);
      fetchCertificates();
    } catch (e) {
      setVerifyResult({ valid: false, reason: (e as Error).message });
    } finally {
      setVerifying(false);
    }
  };

  const handleExportJson = (cert: WardenCertificate) => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(cert, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `warden-cert-${cert.tool.name}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const handleImportCertificate = async () => {
    setImportStatus(null);
    try {
      let certData;
      try {
        certData = JSON.parse(importJson);
      } catch (e) {
        throw new Error('Invalid JSON format.');
      }

      const res = await fetch('/v1/certificates/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(certData),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Import failed');
      }

      setImportStatus('Certificate imported & verified successfully.');
      fetchCertificates();
      setTimeout(() => {
        setImportModalOpen(false);
        setImportJson('');
        setSelectedFileName(null);
        setSelectedFileSize(null);
        setFileError(null);
        setImportStatus(null);
      }, 1500);
    } catch (e) {
      setImportStatus(`Import Error: ${(e as Error).message}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-cyan-500/20 pb-4">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center space-x-2">
            <Award size={22} className="text-cyan-400" />
            <span>Trust Certificate Manager</span>
          </h2>
          <p className="text-slate-400 text-xs mt-0.5 font-mono">
            Signed Ed25519 JSON certificate registry asserting tool capabilities and security decisions.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => setImportModalOpen(true)}
            className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-xl btn-shiny-glass text-xs font-semibold cursor-pointer"
          >
            <Upload size={14} className="text-cyan-400" />
            <span>Import Certificate</span>
          </button>
          <button
            onClick={fetchCertificates}
            className="p-2 rounded-xl bg-slate-900/80 hover:bg-slate-800 text-slate-300 border border-slate-700/80 transition-all cursor-pointer shadow-sm"
          >
            <RefreshCw size={14} />
          </button>
        </div>
      </div>

      {/* Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Certificate List Column */}
        <div className="glass-panel p-4 space-y-4">
          <div className="relative">
            <Search size={14} className="text-slate-400 absolute left-3 top-3" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search tools or hashes..."
              className="w-full pl-9 pr-3 py-2 rounded-xl bg-slate-950/80 border border-slate-800 text-xs font-mono text-cyan-300 placeholder-slate-500 focus:outline-none focus:border-cyan-500 shadow-inner"
            />
          </div>

          <div className="space-y-2 max-h-[560px] overflow-y-auto pr-1">
            {certificates.length === 0 ? (
              <div className="p-8 text-center text-slate-500 text-xs font-mono">No certificates found.</div>
            ) : (
              certificates.map((cert) => (
                <div
                  key={cert.certificate_id}
                  onClick={() => handleSelectCert(cert)}
                  className={`p-3.5 rounded-xl cursor-pointer transition-all border ${
                    selectedCert?.certificate_id === cert.certificate_id
                      ? 'bg-cyan-950/30 border-cyan-500/50 shadow-md shadow-cyan-950/30'
                      : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-white">{cert.tool.name}</span>
                    <span
                      className={`text-[10px] uppercase font-mono font-bold px-2 py-0.5 rounded-full ${
                        cert.status === 'active' ? 'badge-allow' : 'badge-block'
                      }`}
                    >
                      {cert.status}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 font-mono mt-1">
                    {cert.tool.hash.substring(0, 22)}...
                  </div>
                  <div className="text-[10px] text-slate-500 mt-2 flex items-center justify-between font-mono">
                    <span>{new Date(cert.issued_at).toLocaleDateString()}</span>
                    <span className="text-cyan-400 uppercase font-bold">{cert.decision.outcome}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Certificate Detail Column */}
        {selectedCert && (
          <div className="lg:col-span-2 glass-panel p-5 space-y-5">
            {/* Cert Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-cyan-500/20">
              <div className="space-y-1">
                <div className="flex items-center space-x-2">
                  <h3 className="text-lg font-bold text-white font-mono">{selectedCert.tool.name}</h3>
                  <span className="px-2 py-0.5 rounded-md text-xs font-mono bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                    v{selectedCert.tool.version}
                  </span>
                </div>
                <p className="text-xs text-slate-400 font-mono">ID: {selectedCert.certificate_id}</p>
              </div>

              <button
                onClick={() => handleExportJson(selectedCert)}
                className="flex items-center space-x-2 px-4 py-2 rounded-xl btn-shiny-cyan text-xs font-mono shrink-0 cursor-pointer"
              >
                <Download size={14} />
                <span>Export Signed JSON</span>
              </button>
            </div>

            {/* Badges */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono">
              <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1">
                <span className="text-[10px] text-slate-400 uppercase font-semibold">Signature</span>
                <div className="text-xs font-bold text-emerald-400 flex items-center space-x-1.5">
                  <ShieldCheck size={15} />
                  <span>Ed25519 Validated</span>
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1">
                <span className="text-[10px] text-slate-400 uppercase font-semibold">Policy Outcome</span>
                <div className="text-xs font-bold text-cyan-300 uppercase">
                  {selectedCert.decision.outcome}
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1">
                <span className="text-[10px] text-slate-400 uppercase font-semibold">Issuer Org</span>
                <div className="text-xs font-bold text-slate-200 truncate">
                  {selectedCert.issuer.org_name}
                </div>
              </div>
            </div>

            {/* Certificate Details */}
            <div className="space-y-4 font-mono">
              <div className="space-y-1.5">
                <span className="text-xs font-semibold text-cyan-300 uppercase">Approved Capabilities</span>
                <div className="flex flex-wrap gap-2 pt-0.5">
                  {selectedCert.approved_capabilities.map((cap, i) => (
                    <span key={i} className="px-3 py-1 rounded-lg text-xs bg-cyan-950/40 text-cyan-300 border border-cyan-500/30">
                      {cap}
                    </span>
                  ))}
                </div>
              </div>

              <div className="space-y-1.5">
                <span className="text-xs font-semibold text-cyan-300 uppercase">Canonical SHA-256 Hash</span>
                <div className="p-3 rounded-xl code-container text-xs text-slate-200 break-all select-all font-semibold">
                  {selectedCert.tool.hash}
                </div>
              </div>

              <div className="space-y-1.5">
                <span className="text-xs font-semibold text-cyan-300 uppercase">Ed25519 Digital Signature</span>
                <div className="p-3 rounded-xl code-container text-xs text-slate-400 break-all select-all">
                  {selectedCert.signature}
                </div>
              </div>
            </div>

            {/* Live Hash Verification Widget */}
            <div className="p-4 rounded-2xl bg-slate-950/90 border border-slate-800 space-y-3 shadow-inner">
              <div className="flex items-center space-x-2">
                <Lock size={15} className="text-cyan-400" />
                <h4 className="text-xs font-bold text-white uppercase font-mono tracking-wider">Live Tool Hash Verification Test</h4>
              </div>
              <p className="text-xs text-slate-400 font-mono">
                Verify this certificate against a target tool hash. Modifying the live tool hash simulates code tampering.
              </p>
              <div className="flex flex-col sm:flex-row gap-2">
                <input
                  type="text"
                  value={verifyHashInput}
                  onChange={(e) => setVerifyHashInput(e.target.value)}
                  className="flex-1 px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-800 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
                  placeholder="Tool SHA-256 hash..."
                />
                <button
                  onClick={handleVerifyHash}
                  disabled={verifying}
                  className="px-4 py-2 rounded-xl btn-shiny-cyan text-xs font-mono shrink-0 cursor-pointer"
                >
                  {verifying ? 'Verifying...' : 'Verify Hash'}
                </button>
              </div>

              {verifyResult && (
                <div className={`p-3 rounded-xl text-xs font-mono space-y-1 ${
                  verifyResult.valid ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-300' : 'bg-rose-500/10 border border-rose-500/30 text-rose-300'
                }`}>
                  <div className="font-semibold flex items-center space-x-1.5">
                    {verifyResult.valid ? <CheckCircle2 size={15} /> : <XCircle size={15} />}
                    <span>{verifyResult.valid ? 'Verification Passed' : 'Verification Failed'}</span>
                  </div>
                  <p className="text-xs">{verifyResult.reason}</p>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Import Modal */}
      {importModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="glass-panel p-6 max-w-lg w-full space-y-4 border border-cyan-500/30">
            <h3 className="text-base font-bold text-white flex items-center space-x-2 font-mono">
              <Upload size={18} className="text-cyan-400" />
              <span>Import Trust Certificate JSON</span>
            </h3>

            {/* Tabs */}
            <div className="flex border-b border-slate-800 font-mono text-xs">
              <button
                onClick={() => {
                  setUploadTab('upload');
                  setImportStatus(null);
                }}
                className={`pb-2.5 px-4 font-semibold border-b-2 transition-all cursor-pointer ${
                  uploadTab === 'upload'
                    ? 'border-cyan-500 text-cyan-400'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                Upload File
              </button>
              <button
                onClick={() => {
                  setUploadTab('raw');
                  setImportStatus(null);
                }}
                className={`pb-2.5 px-4 font-semibold border-b-2 transition-all cursor-pointer ${
                  uploadTab === 'raw'
                    ? 'border-cyan-500 text-cyan-400'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                Paste Raw JSON
              </button>
            </div>

            {uploadTab === 'upload' ? (
              <div className="space-y-4 font-mono">
                {!selectedFileName ? (
                  <div
                    onDragEnter={handleDrag}
                    onDragOver={handleDrag}
                    onDragLeave={handleDrag}
                    onDrop={handleDrop}
                    className={`relative group cursor-pointer border-2 border-dashed rounded-2xl p-8 text-center flex flex-col items-center justify-center space-y-3 transition-all ${
                      dragActive
                        ? 'border-cyan-400 bg-cyan-950/20 shadow-lg shadow-cyan-500/10'
                        : 'border-slate-800 bg-slate-950/40 hover:border-slate-700 hover:bg-slate-900/40'
                    }`}
                    onClick={() => document.getElementById('file-upload-input')?.click()}
                  >
                    <input
                      id="file-upload-input"
                      type="file"
                      accept=".json"
                      onChange={handleFileSelect}
                      className="hidden"
                    />
                    <div className="p-3 rounded-2xl bg-cyan-950/40 border border-cyan-500/20 group-hover:border-cyan-500/40 text-cyan-400 transition-colors">
                      <Upload size={22} className="group-hover:scale-110 transition-transform duration-200" />
                    </div>
                    <div>
                      <p className="text-xs font-semibold text-slate-200">
                        Drag and drop your trust certificate, or <span className="text-cyan-400 group-hover:underline font-bold">browse</span>
                      </p>
                      <p className="text-[10px] text-slate-500 mt-1">Supports only .json certificates</p>
                    </div>
                  </div>
                ) : (
                  <div className="p-4 rounded-2xl bg-slate-950/60 border border-slate-800 flex items-center justify-between">
                    <div className="flex items-center space-x-3 min-w-0">
                      <div className="p-2.5 rounded-xl bg-cyan-950/40 border border-cyan-500/25 text-cyan-400">
                        <FileJson size={18} />
                      </div>
                      <div className="min-w-0">
                        <p className="text-xs font-bold text-slate-200 truncate">{selectedFileName}</p>
                        <p className="text-[10px] text-slate-500">{selectedFileSize}</p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      {fileError ? (
                        <span className="text-[10px] uppercase font-bold badge-block px-2.5 py-0.5 rounded-full">Error</span>
                      ) : (
                        <span className="text-[10px] uppercase font-bold badge-allow px-2.5 py-0.5 rounded-full">Ready</span>
                      )}
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          clearFile();
                        }}
                        className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 hover:border-slate-700 transition-all cursor-pointer"
                        title="Remove file"
                      >
                        <X size={13} />
                      </button>
                    </div>
                  </div>
                )}
                {fileError && (
                  <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-[11px] leading-relaxed">
                    {fileError}
                  </div>
                )}
              </div>
            ) : (
              <div className="space-y-2">
                <textarea
                  rows={9}
                  value={importJson}
                  onChange={(e) => setImportJson(e.target.value)}
                  placeholder="Paste JSON certificate here..."
                  className="w-full p-3.5 rounded-xl code-container text-xs text-cyan-300 focus:outline-none focus:border-cyan-500 font-mono leading-relaxed"
                />
              </div>
            )}

            {importStatus && (
              <div className="text-xs font-mono p-3 rounded-xl bg-slate-950 border border-slate-800 text-slate-300">
                {importStatus}
              </div>
            )}
            <div className="flex justify-end space-x-3 pt-2 font-mono">
              <button
                onClick={() => {
                  setImportModalOpen(false);
                  clearFile();
                  setImportStatus(null);
                }}
                className="px-4 py-2 rounded-xl btn-shiny-glass text-xs cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleImportCertificate}
                className="px-4 py-2 rounded-xl btn-shiny-cyan text-xs cursor-pointer"
              >
                Import & Verify Signature
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
