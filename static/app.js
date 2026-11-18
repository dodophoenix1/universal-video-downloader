(() => {
  "use strict";

  const urlInput = document.getElementById("video-url");
  const inspectBtn = document.getElementById("inspect-btn");
  const errorBox = document.getElementById("error-box");
  const errorMsg = document.getElementById("error-msg");
  const previewCard = document.getElementById("preview-card");
  const thumbImg = document.getElementById("video-thumb");
  const thumbPlaceholder = document.getElementById("thumb-placeholder");
  const platformBadge = document.getElementById("platform-badge");
  const durationBadge = document.getElementById("duration-badge");
  const videoTitle = document.getElementById("video-title");
  const videoUploader = document.getElementById("video-uploader");
  const formatButtons = Array.from(document.querySelectorAll(".format-pill"));
  const qualitySelect = document.getElementById("quality-select");
  const downloadBtn = document.getElementById("download-btn");
  const progressSection = document.getElementById("progress-section");
  const progressBar = document.getElementById("progress-bar");
  const progressText = document.getElementById("progress-text");
  const readySection = document.getElementById("ready-section");
  const readyMeta = document.getElementById("ready-meta");
  const saveFileLink = document.getElementById("save-file-link");

  let currentInfo = null;
  let selectedFormat = "mp4";
  let activePollTimer = null;

  function showError(message) {
    errorMsg.textContent = String(message || "เกิดข้อผิดพลาดที่ไม่ทราบสาเหตุ");
    errorBox.classList.remove("hidden");
  }

  function clearError() {
    errorMsg.textContent = "";
    errorBox.classList.add("hidden");
  }

  function setBusy(isBusy) {
    inspectBtn.disabled = isBusy;
    downloadBtn.disabled = isBusy;
    inspectBtn.textContent = isBusy ? "กำลังตรวจสอบ..." : "ตรวจสอบวิดีโอ";
  }

  function resetDownloadState() {
    if (activePollTimer !== null) {
      window.clearTimeout(activePollTimer);
      activePollTimer = null;
    }
    progressSection.classList.add("hidden");
    readySection.classList.add("hidden");
    progressBar.style.width = "0%";
    progressText.textContent = "กำลังเตรียมไฟล์...";
    saveFileLink.removeAttribute("href");
  }

  function populateQualities(fmt) {
    while (qualitySelect.firstChild) {
      qualitySelect.removeChild(qualitySelect.firstChild);
    }

    if (!currentInfo || !currentInfo.formats || !currentInfo.formats[fmt]) {
      downloadBtn.disabled = true;
      return;
    }

    const fmtData = currentInfo.formats[fmt];
    if (!fmtData.available || !Array.isArray(fmtData.qualities) || fmtData.qualities.length === 0) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "ไม่รองรับฟอร์แมตนี้สำหรับวิดีโอนี้";
      qualitySelect.appendChild(opt);
      qualitySelect.disabled = true;
      downloadBtn.disabled = true;
      return;
    }

    qualitySelect.disabled = false;
    downloadBtn.disabled = false;

    for (const q of fmtData.qualities) {
      const opt = document.createElement("option");
      opt.value = String(q.id || "best");
      opt.textContent = String(q.label || q.id || "Best");
      qualitySelect.appendChild(opt);
    }
  }

  function selectFormat(fmt) {
    selectedFormat = fmt;
    for (const btn of formatButtons) {
      const isSelected = btn.dataset.format === fmt;
      btn.setAttribute("aria-pressed", isSelected ? "true" : "false");
      if (isSelected) {
        btn.classList.add("bg-sky-500", "text-slate-950", "border-sky-400", "font-semibold");
        btn.classList.remove("bg-slate-800/80", "text-slate-300", "border-slate-700");
      } else {
        btn.classList.remove("bg-sky-500", "text-slate-950", "border-sky-400", "font-semibold");
        btn.classList.add("bg-slate-800/80", "text-slate-300", "border-slate-700");
      }
    }
    populateQualities(fmt);
  }

  function updateFormatAvailability() {
    if (!currentInfo || !currentInfo.formats) {
      return;
    }
    let fallbackFmt = null;
    for (const btn of formatButtons) {
      const fmt = btn.dataset.format;
      const available = Boolean(currentInfo.formats[fmt] && currentInfo.formats[fmt].available);
      btn.disabled = !available;
      if (available && fallbackFmt === null) {
        fallbackFmt = fmt;
      }
      if (!available) {
        btn.classList.add("opacity-40", "cursor-not-allowed");
      } else {
        btn.classList.remove("opacity-40", "cursor-not-allowed");
      }
    }
    if (!currentInfo.formats[selectedFormat] || !currentInfo.formats[selectedFormat].available) {
      if (fallbackFmt) {
        selectFormat(fallbackFmt);
      }
    } else {
      selectFormat(selectedFormat);
    }
  }

  async function inspectVideo() {
    clearError();
    resetDownloadState();

    const url = urlInput.value.trim();
    if (!url) {
      showError("กรุณาวางลิงก์วิดีโอก่อนครับ (รองรับ http:// หรือ https://)");
      return;
    }

    setBusy(true);
    try {
      const resp = await fetch("/api/info", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.detail || "ไม่สามารถตรวจสอบวิดีโอได้");
      }

      currentInfo = data;
      videoTitle.textContent = String(data.title || "Untitled Media");
      videoUploader.textContent = data.uploader ? "โดย " + String(data.uploader) : "";
      platformBadge.textContent = String(data.platform || "Web");
      durationBadge.textContent = String(data.duration_text || "--:--");

      if (typeof data.thumbnail === "string" && /^https?:\/\//i.test(data.thumbnail)) {
        thumbImg.src = data.thumbnail;
        thumbImg.classList.remove("hidden");
        thumbPlaceholder.classList.add("hidden");
      } else {
        thumbImg.removeAttribute("src");
        thumbImg.classList.add("hidden");
        thumbPlaceholder.classList.remove("hidden");
      }

      updateFormatAvailability();
      previewCard.classList.remove("hidden");
    } catch (err) {
      previewCard.classList.add("hidden");
      showError(err instanceof Error ? err.message : "ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์ได้");
    } finally {
      setBusy(false);
    }
  }

  async function pollJob(jobId) {
    try {
      const resp = await fetch("/api/jobs/" + encodeURIComponent(jobId), {
        method: "GET",
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.detail || "ไม่สามารถติดตามสถานะงานได้");
      }

      const pct = Math.max(0, Math.min(100, Number(data.progress || 0)));
      progressBar.style.width = pct + "%";

      if (data.status === "queued" || data.status === "downloading") {
        progressText.textContent =
          data.status === "queued"
            ? "อยู่ในคิวกำลังเริ่มดาวน์โหลด..."
            : "กำลังดาวน์โหลดและประมวลผล (" + pct + "%)...";
        activePollTimer = window.setTimeout(() => pollJob(jobId), 700);
        return;
      }

      if (data.status === "ready") {
        if (typeof data.download_url !== "string" || !data.download_url.startsWith("/api/jobs/")) {
          throw new Error("ลิงก์ดาวน์โหลดไม่ถูกต้อง");
        }
        progressBar.style.width = "100%";
        progressText.textContent = "ประมวลผลเสร็จสมบูรณ์!";
        readyMeta.textContent = data.filesize_text
          ? "ขนาดไฟล์: " + String(data.filesize_text) + " (ลบอัตโนมัติหลังดาวน์โหลดเสร็จ)"
          : "พร้อมดาวน์โหลดแล้ว (ลบอัตโนมัติหลังดาวน์โหลดเสร็จ)";
        saveFileLink.href = data.download_url;
        readySection.classList.remove("hidden");
        downloadBtn.disabled = false;
        return;
      }

      if (data.status === "error") {
        throw new Error(data.error || "การดาวน์โหลดล้มเหลว");
      }
    } catch (err) {
      progressSection.classList.add("hidden");
      downloadBtn.disabled = false;
      showError(err instanceof Error ? err.message : "เกิดข้อผิดพลาดระหว่างดาวน์โหลด");
    }
  }

  async function startDownloadJob() {
    clearError();
    resetDownloadState();

    const url = urlInput.value.trim();
    const quality = qualitySelect.value || "best";
    if (!url) {
      showError("กรุณาระบุ URL วิดีโอก่อนดาวน์โหลด");
      return;
    }

    downloadBtn.disabled = true;
    progressSection.classList.remove("hidden");
    progressBar.style.width = "5%";
    progressText.textContent = "กำลังสร้างงานดาวน์โหลด...";

    try {
      const resp = await fetch("/api/jobs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url,
          format: selectedFormat,
          quality,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.detail || "ไม่สามารถสร้างงานดาวน์โหลดได้");
      }
      await pollJob(data.job_id);
    } catch (err) {
      progressSection.classList.add("hidden");
      downloadBtn.disabled = false;
      showError(err instanceof Error ? err.message : "เกิดข้อผิดพลาดระหว่างเริ่มต้นดาวน์โหลด");
    }
  }

  inspectBtn.addEventListener("click", inspectVideo);
  urlInput.addEventListener("keydown", (evt) => {
    if (evt.key === "Enter") {
      evt.preventDefault();
      inspectVideo();
    }
  });
  for (const btn of formatButtons) {
    btn.addEventListener("click", () => {
      if (!btn.disabled && btn.dataset.format) {
        selectFormat(btn.dataset.format);
      }
    });
  }
  downloadBtn.addEventListener("click", startDownloadJob);
  saveFileLink.addEventListener("click", () => {
    window.setTimeout(() => {
      readySection.classList.add("hidden");
      progressSection.classList.add("hidden");
    }, 1200);
  });
})();
