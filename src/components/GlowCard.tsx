import React, { useEffect, useRef, type ReactNode } from "react";
import "./GlowCard.css";

interface GlowCardProps {
  children: ReactNode;
  className?: string;
  glowColor?: "blue" | "purple" | "green" | "red" | "orange";
}

const glowColors = {
  blue: "220",
  purple: "280",
  green: "120",
  red: "0",
  orange: "30",
};

export default function GlowCard({
  children,
  className = "",
  glowColor = "green",
}: GlowCardProps) {
  const cardRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const card = cardRef.current;
    if (!card) return;

    const updatePointer = (event: PointerEvent) => {
      const rect = card.getBoundingClientRect();
      card.style.setProperty("--pointer-x", `${event.clientX - rect.left}px`);
      card.style.setProperty("--pointer-y", `${event.clientY - rect.top}px`);
    };

    const clearPointer = () => {
      card.style.setProperty("--pointer-x", "-1000px");
      card.style.setProperty("--pointer-y", "-1000px");
    };

    card.addEventListener("pointermove", updatePointer);
    card.addEventListener("pointerleave", clearPointer);

    return () => {
      card.removeEventListener("pointermove", updatePointer);
      card.removeEventListener("pointerleave", clearPointer);
    };
  }, []);

  return (
    <div
      ref={cardRef}
      className={`glow-card ${className}`}
      style={{ "--glow-hue": glowColors[glowColor] } as React.CSSProperties}
    >
      <div className="glow-card__content">{children}</div>
    </div>
  );
}
