"use strict";

const element = (name) => document.getElementById(name);
const status = element("status");
const download = element("download");
const retry = element("retry");
const fallback = element("fallback");
const fragment = location.hash;
if (fragment) history.replaceState(null, "", location.pathname);

function control() {
  const workers = navigator.serviceWorker;
  if (!workers) throw new Error("Service workers unavailable.");
  const script = new URL("profile-worker.js", location.href).href;
  return workers.register("profile-worker.js", {scope: "./", updateViaCache: "none"}).then(() =>
    new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        workers.removeEventListener("controllerchange", ready);
        reject(new Error("Download handler took too long to start."));
      }, 7000);
      function ready() {
        if (workers.controller?.scriptURL !== script) return;
        clearTimeout(timer);
        workers.removeEventListener("controllerchange", ready);
        resolve(workers.controller);
      }
      workers.addEventListener("controllerchange", ready);
      ready();
    }));
}

function stage(worker) {
  const channel = new MessageChannel();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      channel.port1.close();
      reject(new Error("Download handler timed out."));
    }, 5000);
    channel.port1.onmessage = ({data}) => {
      clearTimeout(timer);
      channel.port1.close();
      const ticket = data?.ticket;
      if (typeof ticket !== "string" || !/^[0-9a-f-]{36}$/.test(ticket)) reject(new Error("Profile not prepared."));
      else resolve(ticket);
    };
    worker.postMessage({action: "prepare", fragment}, [channel.port2]);
  });
}

async function prepare() {
  retry.hidden = true;
  download.hidden = true;
  status.textContent = "Preparing the profile on this device…";
  try {
    const ticket = await stage(await control());
    download.href = "project-chat-companion.mobileconfig?download=" + ticket;
    download.hidden = false;
    status.textContent = "Profile ready. Compare the fingerprint before downloading.";
  } catch {
    status.textContent = "This browser couldn’t prepare the profile download. Open this setup QR in Safari or use desktop export.";
    retry.hidden = false;
    fallback.hidden = false;
  }
}

download.addEventListener("click", () => {
  status.textContent = "If Safari asks to download a configuration profile, choose Allow. Then open Settings.";
  retry.hidden = false;
  fallback.hidden = false;
});
retry.addEventListener("click", prepare);

(async () => {
  if (!fragment) {
    status.textContent = "Scan the iPhone/iPad setup QR from Project Chat on Ubuntu.";
    return;
  }
  try {
    const certificate = await ProjectChatProfile.validate(fragment);
    element("fingerprint").textContent = certificate.fingerprint;
    element("details").hidden = false;
    await prepare();
  } catch {
    status.textContent = "This setup QR is invalid, expired, or from an unsupported version. Scan a fresh setup QR from Ubuntu.";
    fallback.hidden = false;
  }
})();
