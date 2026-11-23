
// ========================================
// PHISHGUARD POPUP
// ========================================

chrome.tabs.query(
    { active: true, currentWindow: true },
    async function (tabs) {

        const tab = tabs[0];

        // ========================================
        // V1: ANALYZE URL
        // ========================================

        const urlResult = analyzeURL(tab.url);


        // ========================================
        // V2: ANALYZE WEBPAGE
        // ========================================

        let pageResult;

        try {

            const results =
                await chrome.scripting.executeScript({

                    target: {
                        tabId: tab.id
                    },

                    func: analyzePage

                });

            pageResult = results[0].result;

        } catch (error) {

            console.error(
                "Page analysis failed:",
                error
            );

            pageResult = {

                score: 0,

                warnings: [
                    "Could not analyze webpage"
                ],

                externalLinks: []

            };
        }


        // ========================================
        // COMBINE SCORES
        // ========================================

        let totalScore =
            urlResult.score + pageResult.score;

        if (totalScore > 100) {
            totalScore = 100;
        }


        // ========================================
        // DISPLAY SCORE
        // ========================================

        document.getElementById(
            "scoreNumber"
        ).textContent = totalScore;

        const status =
            document.getElementById("status");

        if (totalScore < 30) {

            status.textContent = "Low Risk";

        } else if (totalScore < 60) {

            status.textContent = "Suspicious";

        } else {

            status.textContent = "High Risk";

        }


        // ========================================
        // DISPLAY WARNINGS
        // ========================================

        const warningList =
            document.getElementById("warnings");

        warningList.innerHTML = "";

        const allWarnings = [
            ...urlResult.warnings,
            ...pageResult.warnings
        ];

        if (allWarnings.length === 0) {

            const item =
                document.createElement("li");

            item.textContent =
                "No obvious phishing indicators found.";

            warningList.appendChild(item);

        } else {

            for (let warning of allWarnings) {

                const item =
                    document.createElement("li");

                item.textContent = warning;

                warningList.appendChild(item);
            }
        }


        // ========================================
        // EXTERNAL LINKS DROPDOWN
        // ========================================

        const externalLinks =
            pageResult.externalLinks || [];

        const externalLinksButton =
            document.getElementById(
                "externalLinksButton"
            );

        const externalLinksList =
            document.getElementById(
                "externalLinksList"
            );

        externalLinksList.innerHTML = "";

        // Update dropdown title
        externalLinksButton.innerHTML =
            "External Links (" +
            externalLinks.length +
            ') <span id="arrow">▼</span>';


        // Display external domains
        if (externalLinks.length === 0) {

            const div =
                document.createElement("div");

            div.className = "external-link";

            div.textContent =
                "No external links detected.";

            externalLinksList.appendChild(div);

        } else {

            for (let domain of externalLinks) {

                const div =
                    document.createElement("div");

                div.className = "external-link";

                div.textContent = domain;

                externalLinksList.appendChild(div);
            }
        }


        // ========================================
        // DROPDOWN BUTTON
        // ========================================

        externalLinksButton.addEventListener(
            "click",
            function () {

                externalLinksList.classList.toggle("show");

                const arrow =
                    document.getElementById("arrow");

                if (
                    externalLinksList.classList.contains("show")
                ) {

                    arrow.textContent = "▲";

                } else {

                    arrow.textContent = "▼";

                }
            }
        );

    }
);
