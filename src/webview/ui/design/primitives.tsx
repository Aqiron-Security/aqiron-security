import React from 'react';
import { Severity } from '../types.js';

export function AqironButton({ variant = 'secondary', className = '', ...props }: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'ghost' | 'danger' }): React.ReactElement {
	return <button {...props} className={`aq-button aq-button--${variant}${className ? ` ${className}` : ''}`} />;
}

export function AqironIconButton({ className = '', ...props }: React.ButtonHTMLAttributes<HTMLButtonElement>): React.ReactElement {
	return <button {...props} className={`aq-icon-button${className ? ` ${className}` : ''}`} />;
}

export function AqironMetric({ title, value }: { title: string; value: string }): React.ReactElement {
	return <div className="metric aq-metric"><strong className="aq-metric__value">{value}</strong><span className="aq-metric__label">{title}</span></div>;
}

export function AqironBadge({ children, tone = 'neutral', className = '' }: { children: React.ReactNode; tone?: 'neutral' | 'brand' | 'ai'; className?: string }): React.ReactElement {
	return <span className={`aq-badge aq-badge--${tone}${className ? ` ${className}` : ''}`}>{children}</span>;
}

export function AqironSeverity({ severity }: { severity: Severity }): React.ReactElement {
	return <span className={`aq-badge aq-severity sev sev-${severity.toLowerCase()}`} style={{ '--aq-severity-color': `var(--aq-color-severity-${severity.toLowerCase()})` } as React.CSSProperties}>{severity}</span>;
}

export function AqironSectionHeader({ title, description, action }: { title: string; description?: React.ReactNode; action?: React.ReactNode }): React.ReactElement {
	return <div className="aq-section-header section-head"><div className="aq-section-header__copy"><h2 className="aq-section-header__title">{title}</h2>{description && <span className="aq-section-header__description">{description}</span>}</div>{action}</div>;
}
