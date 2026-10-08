import { forwardRef, useEffect, useImperativeHandle, useRef, useState } from 'react';
import ChatMessage from './ChatMessage';
import ChatInput from './ChatInput';
import ContextBubble from './ContextBubble';
import { aiApi } from '../../utils/aiApi';

function buildFindingContextMessage(finding) {
  return `I'm now focused on **${finding.ruleId}** — "${finding.ruleName}".

**Resource:** \`${finding.resourceName}\` (${finding.resourceGroup})
**Severity:** ${finding.severity} · **Category:** ${finding.category}

${finding.description}

Ask me anything about this finding — remediation steps, risk impact, validation, or related compliance controls.`;
}

const ChatPanel = forwardRef(function ChatPanel({ initialMessages = [], contextFinding, suggestions = [] }, ref) {
  const [messages, setMessages] = useState(initialMessages);
  const [thinking, setThinking] = useState(false);
  const bottomRef = useRef(null);

  useImperativeHandle(ref, () => ({ send: handleSend }));

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, thinking]);

  // Inject context message when selected finding changes
  useEffect(() => {
    if (!contextFinding) return;
    const msg = {
      id: Date.now(),
      role: 'assistant',
      content: buildFindingContextMessage(contextFinding),
      sources: [{ id: contextFinding.ruleId, resource: contextFinding.resourceName }],
      timestamp: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, msg]);
  }, [contextFinding]);

  async function handleSend(text) {
    if (!text?.trim()) return;
    const userMsg = { id: Date.now(), role: 'user', content: text, timestamp: new Date().toISOString() };
    setMessages((prev) => [...prev, userMsg]);
    setThinking(true);

    try {
      const result = await aiApi.chat({ question: text });
      const aiMsg = {
        id: Date.now() + 1,
        role: 'assistant',
        content: result.answer ?? result,
        sources: result.sources ?? [],
        timestamp: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, aiMsg]);
    } catch {
      const errMsg = {
        id: Date.now() + 1,
        role: 'assistant',
        content: 'Something went wrong. Please try again.',
        sources: [],
        timestamp: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, errMsg]);
    } finally {
      setThinking(false);
    }
  }

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar">
        {messages.map((msg) => (
          <ChatMessage key={msg.id} message={msg} />
        ))}
        <ContextBubble thinking={thinking} />
        <div ref={bottomRef} />
      </div>

      {/* Thin suggestions strip — single scrollable row, no wrapping */}
      {suggestions.length > 0 && (
        <div className="flex-shrink-0 overflow-x-auto no-scrollbar border-t border-border-light dark:border-border-dark px-3 py-1.5 flex gap-1.5">
          {suggestions.map((s, i) => (
            <button
              key={i}
              onClick={() => handleSend(s)}
              disabled={thinking}
              className="flex-shrink-0 text-[11px] text-text-secondary dark:text-text-dark-tertiary px-2.5 py-1 rounded-lg border border-border-light dark:border-border-dark bg-bg-secondary dark:bg-bg-dark-tertiary hover:bg-bg-tertiary dark:hover:bg-border-dark hover:text-text-primary dark:hover:text-text-dark-primary disabled:opacity-40 transition-colors whitespace-nowrap"
            >
              {s}
            </button>
          ))}
        </div>
      )}

      <ChatInput onSend={handleSend} disabled={thinking} />
    </div>
  );
});

export default ChatPanel;
