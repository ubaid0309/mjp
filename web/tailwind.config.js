/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: { DEFAULT: "#0E1726", 2: "#121D2F" },
        panel: { DEFAULT: "#152033", 2: "#1B2840", 3: "#22314D" },
        line: { DEFAULT: "#26344F", strong: "#34466A" },
        fg: { DEFAULT: "#DCE4F0", muted: "#8E9CB5", faint: "#5F6E89" },
        accent: { DEFAULT: "#3FB8D8", strong: "#62CBE6", ink: "#062330" },
        link: "#7DA2FF",
        sev: { critical: "#E5484D", high: "#F08A4B", medium: "#E3B341", low: "#5AA9E6", info: "#7E8BA3" },
        ok: "#3DBE8B",
      },
      fontFamily: {
        sans: ['"IBM Plex Sans"', "system-ui", "sans-serif"],
        mono: ['"IBM Plex Mono"', "ui-monospace", "monospace"],
      },
      fontSize: { "2xs": ["11px", "16px"] },
    },
  },
  plugins: [],
};
