
import type { ReactNode } from "react";
import "./ShinyButton.css";

interface ShinyButtonProps {
  children: ReactNode;
  onClick?: () => void;
  className?: string;
}

export function ShinyButton({
  children,
  onClick,
  className = "",
}: ShinyButtonProps) {
  return (
    <button
      className={`shiny-cta ${className}`}
      onClick={onClick}
    >
      <span>{children}</span>
    </button>
  );
}

