import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-jetbrains-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Kaaval — Security Visibility Platform",
  description: "Unified security visibility: agent, cloud CSPM, integrations, customizable dashboard",
};

import Sidebar from "../components/Sidebar";
import { AuthProvider } from "../components/AuthContext";
import TopBar from "../components/TopBar";
import { ThemeProvider } from "../components/ThemeContext";

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${inter.variable} ${jetbrainsMono.variable} bg-space text-gray-200 font-sans min-h-screen selection:bg-neon-green/30 overflow-hidden`}>
        <ThemeProvider>
          <AuthProvider>
            <div className="flex h-screen">
              <Sidebar />
              <div className="flex-1 flex flex-col min-w-0 overflow-hidden ml-64">
                <TopBar />
                <main className="flex-1 overflow-y-auto p-8 relative scrollbar-thin scrollbar-thumb-gray-800 scrollbar-track-transparent">
                  <div className="absolute inset-0 z-[-1] bg-[linear-gradient(rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.02)_1px,transparent_1px)] bg-[size:50px_50px] pointer-events-none"></div>
                  <div className="max-w-7xl mx-auto">
                    {children}
                  </div>
                </main>
              </div>
            </div>
          </AuthProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
