import type { Config } from "tailwindcss";

const config: Config = {
    content: [
        "./app/**/*.{js,ts,jsx,tsx,mdx}",
        "./components/**/*.{js,ts,jsx,tsx,mdx}",
    ],
    theme: {
        extend: {
            colors: {
                background: "var(--bg-space)",
                foreground: "var(--text-primary)",
                space: "var(--bg-space)",
                surface: "var(--surface)",
                card: "var(--card-bg)",
                nav: "var(--nav-bg)",
                "text-secondary": "var(--text-secondary)",
                "tab-active-text": "var(--tab-active-text)",
                "neon-blue": "var(--neon-blue)",
                "neon-green": "var(--neon-green)",
                "neon-purple": "var(--neon-purple)",
                "neon-red": "var(--neon-red)",
            },
            fontFamily: {
                sans: ["var(--font-inter)"],
                mono: ["var(--font-jetbrains-mono)"],
            },
            backgroundImage: {
                'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
                'grid-pattern': "linear-gradient(rgba(255,255,255,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.03) 1px, transparent 1px)",
            },
        },
    },
    plugins: [],
};
export default config;
