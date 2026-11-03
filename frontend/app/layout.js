import "../styles/globals.css";
import Shell from "./components/Shell";

export const metadata = {
  title: "FihhGuard — don’t get hooked",
  description: "A friendly phishing detector for links and pages.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <Shell>{children}</Shell>
      </body>
    </html>
  );
}
