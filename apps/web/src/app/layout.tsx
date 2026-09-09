import type { Metadata } from "next";
import "./globals.css";
import { Providers } from "@/lib/providers";
export const metadata: Metadata = {
  title: "SentinelAI · Security operations",
  description:
    "Open-source intelligent SOC for small security teams. Synthetic portfolio demonstration.",
};
export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
