// =====================================================================
// PhishGuard - Detection Engine
// =====================================================================

function checkEmail() {
  let email = document.getElementById("emailInput").value.toLowerCase().trim();

  let score = 0;
  let maxScore = 20;

  let issues = []; // { issues store here. }
  let mitigation = [];

  let anomaliesList = document.getElementById("anomaliesList");
  let riskBadge = document.getElementById("riskBadge");

  if (email === "") {
    anomaliesList.innerHTML =
      "<p class='empty-hint'>Please paste an email first.</p>";
    riskBadge.className = "risk-badge idle";
    riskBadge.textContent = "— Awaiting Scan";
    return;
  }

  // ===========================
  // Suspicious Keywords
  // ===========================

  let keywords = [
    "urgent",
    "verify",
    "click here",
    "winner",
    "free",
    "lottery",
    "password",
    "bank",
    "login",
    "account suspended",
    "update now",
    "limited time",
    "confirm",
    "security alert",
    "action required",
    "reset password",
    "your account",
    "immediately",
  ];

  keywords.forEach(function (word) {
    if (email.includes(word)) {
      score += 2;

      issues.push({
        type: "warning",
        icon: `<span class="material-symbols-outlined">
warning
</span>`,
        title: "Suspicious Keyword",
        detail:
          'Detected imperative/social-engineering phrase: "' + word + '".',
      });
    }
  });

  // ===========================
  // Detect Links
  // ===========================

  let links = email.match(/https?:\/\/[^\s]+/g);

  // Common brand names
  let brandTargets = [
    "microsoft",
    "google",
    "paypal",
    "apple",
    "amazon",
    "facebook",
    "netflix",
    "bank",
  ];
  let homographPattern = /[0-9]/; // digits  e.g. paypa1, micr0soft

  if (links) {
    links.forEach(function (link) {
      score += 2;

      issues.push({
        type: "info",
        icon: `<span class="material-symbols-outlined">
link_2
</span>`,
        title: "URL Found",
        detail: link,
        isCode: true,
      });

      // HTTP Check

      if (link.startsWith("http://")) {
        score += 3;

        issues.push({
          type: "warning",
          icon: `<span class="material-symbols-outlined">
lock_open_right
</span>`,
          title: "Insecure Protocol",
          detail: "Link uses HTTP instead of HTTPS.",
        });
      }

      // IP Address

      if (/\d+\.\d+\.\d+\.\d+/.test(link)) {
        score += 5;

        issues.push({
          type: "danger",
          icon: `<span class="material-symbols-outlined">
warning
</span>`,
          title: "Raw IP Address",
          detail: "IP address used instead of a domain name.",
        });
      }

      // URL Shortener

      if (
        link.includes("bit.ly") ||
        link.includes("tinyurl") ||
        link.includes("goo.gl") ||
        link.includes("t.co") ||
        link.includes("rb.gy")
      ) {
        score += 4;

        issues.push({
          type: "warning",
          icon: `<span class="material-symbols-outlined">
content_cut
</span>`,
          title: "Shortened URL",
          detail: "Shortened link detected - destination is obscured.",
        });
      }

      //check /:\/\/([^/]+)/

      brandTargets.forEach(function (brand) {
        let domainMatch = link.match(/:\/\/([^/]+)/);
        let domain = domainMatch ? domainMatch[1] : "";

        if (
          domain &&
          domain.includes(brand.slice(0, 4)) &&
          !domain.includes(brand)
        ) {
          score += 5;

          issues.push({
            type: "danger",
            icon: "🔀",
            title: "Homograph URL Detected",
            detail:
              'The link "' +
              domain +
              '" uses look-alike characters to spoof "' +
              brand +
              '".',
          });
        }

        if (domain.includes(brand) && homographPattern.test(domain)) {
          score += 3;

          issues.push({
            type: "danger",
            icon: "🔀",
            title: "Homograph URL Detected",
            detail:
              'The link "' +
              domain +
              '" mixes digits into a trusted brand name.',
          });
        }
      });
    });
  }

  // ===========================
  // Password Request
  // ===========================

  if (
    email.includes("password") ||
    email.includes("pin") ||
    email.includes("otp")
  ) {
    score += 4;

    issues.push({
      type: "danger",
      icon: "🔑",
      title: "Credential Harvesting",
      detail: "Email requests sensitive credentials (password / PIN / OTP).",
    });
  }

  // ===========================
  // Payment Request
  // ===========================

  if (
    email.includes("payment") ||
    email.includes("credit card") ||
    email.includes("paypal") ||
    email.includes("bank transfer") ||
    email.includes("invoice")
  ) {
    score += 4;

    issues.push({
      type: "danger",
      icon: "💳",
      title: "Financial Request",
      detail: "Sensitive financial/payment request detected.",
    });
  }

  // ===========================
  // Too Many Exclamation Marks
  // ===========================

  let exclamation = (email.match(/!/g) || []).length;

  if (exclamation >= 3) {
    score += 2;

    issues.push({
      type: "warning",
      icon: "❗",
      title: "Urgency Signal",
      detail:
        "Excessive exclamation marks (" +
        exclamation +
        ") suggest manufactured urgency.",
    });
  }

  // ===========================
  // ALL CAPS
  // ===========================

  let upperWords = email.match(/\b[A-Z]{5,}\b/g);

  if (upperWords && upperWords.length >= 3) {
    score += 2;

    issues.push({
      type: "warning",
      icon: "🔠",
      title: "Urgent Call to Action",
      detail:
        "Excessive capital letters detected: " +
        upperWords.slice(0, 3).join(", ") +
        ".",
    });
  }

  // ===========================
  // Risk Percentage
  // ===========================

  let percentage = Math.round((score / maxScore) * 100);

  if (percentage > 100) {
    percentage = 100;
  }

  // ===========================
  // Risk Level
  // ===========================

  let levelClass = "";
  let levelLabel = "";

  if (percentage <= 20) {
    levelClass = "safe";
    levelLabel = "🟢 Safe Email";
  } else if (percentage <= 45) {
    levelClass = "low";
    levelLabel = "🟡 Low Risk";
  } else if (percentage <= 70) {
    levelClass = "suspicious";
    levelLabel = "🟠 Suspicious";
  } else {
    levelClass = "high";
    levelLabel = "🔴 High Risk";
  }

  // ===========================
  // Mitigation
  // ===========================

  mitigation.push(`<span class="material-symbols-outlined">
link_2
</span> Don't click suspicious links`);
  mitigation.push(`<span class="material-symbols-outlined">
mail
</span> Verify the sender's address`);
  mitigation.push(`<span class="material-symbols-outlined">
lock
</span> Never share passwords or OTPs`);
  mitigation.push(`<span class="material-symbols-outlined">
security 
</span> Enable Two-Factor Authentication`);
  mitigation.push(`<span class="material-symbols-outlined">
attach_file
</span>Open only trusted attachments`);
  mitigation.push(`<span class="material-symbols-outlined">
language
</span> Check URLs before visiting`);
  mitigation.push(`<span class="material-symbols-outlined">
flag
</span> Report to your IT/security team`);

  // ===========================
  // Derived dashboard stats
  // ===========================

  let totalWords = email.split(/\s+/).filter(Boolean).length;
  let suspiciousCount = issues.filter(
    (i) => i.type === "danger" || i.type === "warning",
  ).length;

  let safeSignals = ["unsubscribe", "https", "support@", "regards", "official"];
  let safeTags = safeSignals.filter((sig) => email.includes(sig)).length;

  let aiProbability = Math.min(
    99,
    Math.round(percentage * 0.9 + suspiciousCount * 1.5),
  );
  let spamScore = Math.min(10, score / 4).toFixed(1);
  let knownMatch = issues.some((i) => i.title === "Homograph URL Detected")
    ? "Spoofed Domain"
    : "None";
  let confidence = Math.min(99, 70 + suspiciousCount * 3 + (links ? 5 : 0));

  // ===========================
  // Render — Risk badge / summary
  // ===========================

  riskBadge.className = "risk-badge " + levelClass;
  riskBadge.textContent = levelLabel;

  document.getElementById("confidenceValue").textContent = confidence + "%";
  document.getElementById("riskPercent").textContent = percentage + "%";
  document.getElementById("progressBar").style.width = percentage + "%";

  document.getElementById("aiProbability").textContent = aiProbability + "%";
  document.getElementById("knownMatch").textContent = knownMatch;
  document.getElementById("totalWords").textContent = totalWords;
  document.getElementById("suspiciousCount").textContent = suspiciousCount;
  document.getElementById("safeTags").textContent = safeTags;
  document.getElementById("spamScore").textContent = spamScore;

  // ===========================
  // Render — Anomalies
  // ===========================

  if (issues.length === 0) {
    anomaliesList.innerHTML =
      "<p class='empty-hint'>No suspicious content detected.</p>";
  } else {
    anomaliesList.innerHTML = issues
      .map(function (item) {
        let itemClass =
          item.type === "danger"
            ? ""
            : item.type === "warning"
              ? "warning-item"
              : "info-item";
        let detailHtml = item.isCode
          ? "<code>" + escapeHtml(item.detail) + "</code>"
          : "<span>" + escapeHtml(item.detail) + "</span>";

        return `
                <div class="anomaly-item ${itemClass}">
                    <span class="anomaly-icon">${item.icon}</span>
                    <div class="anomaly-body">
                        <b>${item.title}</b>
                        ${detailHtml}
                    </div>
                </div>
            `;
      })
      .join("");
  }

  // ===========================
  // Render — Mitigation grid
  // ===========================

  document.getElementById("mitigationGrid").innerHTML = mitigation
    .map(function (tip) {
      return `<div class="mitigation-item">${tip}</div>`;
    })
    .join("");
}

// Basic HTML escaping so pasted email content can never inject markup
function escapeHtml(str) {
  let div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

// ===========================
// Toolbar buttons
// ===========================

document.getElementById("clearBtn").addEventListener("click", function () {
  document.getElementById("emailInput").value = "";
  document.getElementById("anomaliesList").innerHTML =
    "<p class='empty-hint'>Run a scan to surface anomalies here.</p>";
  document.getElementById("mitigationGrid").innerHTML = "";

  let riskBadge = document.getElementById("riskBadge");
  riskBadge.className = "risk-badge idle";
  riskBadge.textContent = "— Awaiting Scan";

  document.getElementById("confidenceValue").textContent = "—";
  document.getElementById("riskPercent").textContent = "0%";
  document.getElementById("progressBar").style.width = "0%";
  document.getElementById("aiProbability").textContent = "0%";
  document.getElementById("knownMatch").textContent = "None";
  document.getElementById("totalWords").textContent = "0";
  document.getElementById("suspiciousCount").textContent = "0";
  document.getElementById("safeTags").textContent = "0";
  document.getElementById("spamScore").textContent = "0.0";
});

// Attach button is visual-only in this build (no backend upload target yet)
document.getElementById("attachBtn").addEventListener("click", function () {
  alert(
    "Attachment scanning isn't wired up yet — paste the email text directly for now.",
  );
});
