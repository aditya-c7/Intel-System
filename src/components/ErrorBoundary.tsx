import { Component, type ErrorInfo, type ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
}

/**
 * Top-level render barrier. A crash anywhere in the dashboard is replaced with a small,
 * dependency-free fallback instead of blanking the whole page. The fallback deliberately
 * avoids the app's own components/CSS so it still renders when those are the source of the
 * failure.
 */
export default class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false };

  static getDerivedStateFromError(): State {
    return { hasError: true };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('Unhandled UI error:', error, info.componentStack);
  }

  private handleReset = () => {
    this.setState({ hasError: false });
  };

  render() {
    if (this.state.hasError) {
      return (
        <main
          role="alert"
          style={{
            minHeight: '100vh',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '12px',
            padding: '24px',
            fontFamily: 'system-ui, sans-serif',
            color: '#0f172a',
            background: '#f8fafc',
            textAlign: 'center',
          }}
        >
          <h1 style={{ fontSize: '20px', margin: 0 }}>Something went wrong</h1>
          <p style={{ fontSize: '14px', margin: 0, color: '#475569' }}>
            The dashboard hit an unexpected error. Your data is safe — please try again.
          </p>
          <button
            type="button"
            onClick={this.handleReset}
            style={{
              marginTop: '4px',
              padding: '8px 16px',
              fontSize: '14px',
              borderRadius: '8px',
              border: '1px solid #cbd5e1',
              background: '#ffffff',
              cursor: 'pointer',
            }}
          >
            Try again
          </button>
        </main>
      );
    }

    return this.props.children;
  }
}
