import { initUI } from "./ui";

function installThemeToggle(): void {
	const root = document.documentElement;
	const button = document.getElementById("theme-toggle") as HTMLButtonElement | null;
	if (!button) {
		return;
	}

	const syncThemeButton = (): void => {
		const isDark = root.getAttribute("data-theme") !== "light";
		button.textContent = isDark ? "🌙" : "☀️";
		button.setAttribute("aria-label", isDark ? "Switch to light mode" : "Switch to dark mode");
	};

	syncThemeButton();

	button.addEventListener("click", () => {
		const current = root.getAttribute("data-theme") === "light" ? "light" : "dark";
		const next = current === "dark" ? "light" : "dark";
		root.setAttribute("data-theme", next);
		localStorage.setItem("theme", next);
		syncThemeButton();
	});
}

initUI();
installThemeToggle();
