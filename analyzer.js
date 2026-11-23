
 // ========================================
 // PHISHGUARD V1: URL ANALYZER
 // ========================================

function analyzeURL(url) {

    let score = 0;
    let warnings = [];

    let parsedURL;

    try {
        parsedURL = new URL(url);
    } catch {
        return {
            score: 100,
            warnings: ["Invalid URL"]
        };
    }

    let hostname = parsedURL.hostname;

    // Check HTTPS
    if (parsedURL.protocol !== "https:") {
        score += 20;
        warnings.push("Website is not using HTTPS");
    }

    // Check IP address
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;

    if (ipPattern.test(hostname)) {
        score += 30;
        warnings.push("Website uses an IP address instead of a domain name");
    }

    // Check @ symbol
    if (url.includes("@")) {
        score += 25;
        warnings.push("URL contains an @ symbol");
    }

    // Check URL length
    if (url.length > 100) {
        score += 10;
        warnings.push("URL is unusually long");
    }

    // Check subdomains
    let parts = hostname.split(".");

    if (parts.length > 3) {
        score += 15;
        warnings.push("Website has many subdomains");
    }

    // Check suspicious words
    const suspiciousWords = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "password",
        "confirm"
    ];

    for (let word of suspiciousWords) {

        if (hostname.toLowerCase().includes(word)) {
            score += 10;

            warnings.push(
                "Domain contains suspicious word: " + word
            );

            break;
        }
    }

    if (score > 100) {
        score = 100;
    }

    return {
        score: score,
        warnings: warnings
    };
}


// ========================================
// PHISHGUARD V2: PAGE ANALYZER
// ========================================

function analyzePage() {

    let score = 0;
    let warnings = [];
    let externalLinks = [];

    // ----------------------------------------
    // Detect password fields
    // ----------------------------------------

    const passwordFields =
        document.querySelectorAll('input[type="password"]');

    if (passwordFields.length > 0) {

        score += 15;

        warnings.push(
            "Page contains a password field"
        );
    }


    // ----------------------------------------
    // Detect forms
    // ----------------------------------------

    const forms =
        document.querySelectorAll("form");

    if (forms.length > 0) {

        score += 5;

        warnings.push(
            "Page contains a form"
        );
    }


    // ----------------------------------------
    // Detect suspicious language
    // ----------------------------------------

    const suspiciousPhrases = [
        "verify your account",
        "account suspended",
        "account locked",
        "confirm your identity",
        "verify your identity",
        "password expired",
        "security alert",
        "unusual activity",
        "immediately",
        "urgent"
    ];

    const pageText =
        document.body.innerText.toLowerCase();

    for (let phrase of suspiciousPhrases) {

        if (pageText.includes(phrase)) {

            score += 10;

            warnings.push(
                'Suspicious language detected: "' +
                phrase + '"'
            );
        }
    }


    // ----------------------------------------
    // Detect external links
    // ----------------------------------------

    const links =
        document.querySelectorAll("a");

    for (let link of links) {

        try {

            const linkURL = new URL(
                link.href,
                window.location.href
            );

            if (
                linkURL.hostname !==
                window.location.hostname
            ) {

                // Only add unique domains
                if (!externalLinks.includes(linkURL.hostname)) {

                    externalLinks.push(
                        linkURL.hostname
                    );
                }
            }

        } catch {
            // Ignore invalid links
        }
    }


    // ----------------------------------------
    // Limit score
    // ----------------------------------------

    if (score > 100) {
        score = 100;
    }


    // ----------------------------------------
    // Return results
    // ----------------------------------------

    return {
        score: score,
        warnings: warnings,
        externalLinks: externalLinks
    };
}
