import { Link, useLocation } from "react-router-dom";
import { Shield, Search, BarChart3, Database, LogOut, User, FileText } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";

const navItems = [
  { path: "/", label: "Scanner", icon: Search },
  { path: "/dashboard", label: "Dashboard", icon: BarChart3 },
  { path: "/datasets", label: "Datasets", icon: Database },
  { path: "/bulk-scan", label: "Bulk Scan", icon: FileText },
];

export function Navbar() {
  const { pathname } = useLocation();
  const { user, signOut } = useAuth();

  return (
    <nav className="sticky top-0 z-50 border-b border-border bg-background/80 backdrop-blur-xl">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-3">
        <Link to="/" className="flex items-center gap-2">
          <Shield className="h-6 w-6 text-primary text-glow-primary" />
          <span className="font-mono text-lg font-bold text-foreground">
            Phish<span className="text-primary">Guard</span>
          </span>
        </Link>

        <div className="flex items-center gap-1">
          {navItems.map(({ path, label, icon: Icon }) => (
            <Link
              key={path}
              to={path}
              className={`flex items-center gap-1.5 rounded-md px-3 py-2 font-mono text-xs transition-colors ${
                pathname === path
                  ? "bg-primary/10 text-primary"
                  : "text-muted-foreground hover:text-foreground hover:bg-secondary/50"
              }`}
            >
              <Icon className="h-3.5 w-3.5" />
              <span className="hidden sm:inline">{label}</span>
            </Link>
          ))}
        </div>

        <div className="flex items-center gap-2">
          {user ? (
            <>
              <span className="hidden font-mono text-[10px] text-muted-foreground sm:inline">
                {user.email}
              </span>
              <button
                onClick={signOut}
                className="flex items-center gap-1 rounded-md px-2 py-1.5 font-mono text-xs text-muted-foreground transition-colors hover:text-destructive"
              >
                <LogOut className="h-3.5 w-3.5" />
              </button>
            </>
          ) : (
            <Link
              to="/auth"
              className="flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 font-mono text-xs font-bold text-primary-foreground transition-all hover:opacity-90"
            >
              <User className="h-3.5 w-3.5" />
              Sign In
            </Link>
          )}
        </div>
      </div>
    </nav>
  );
}
