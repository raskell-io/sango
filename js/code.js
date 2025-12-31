// =============================================================================
// Code Blocks - Raskell Theme
// Copy button and language labels
// =============================================================================

(function() {
  'use strict';

  // Lucide icons (inline SVG for performance)
  const icons = {
    copy: '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>',
    check: '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>'
  };

  // Language display names
  const languageNames = {
    js: 'JavaScript',
    javascript: 'JavaScript',
    ts: 'TypeScript',
    typescript: 'TypeScript',
    py: 'Python',
    python: 'Python',
    rb: 'Ruby',
    ruby: 'Ruby',
    rs: 'Rust',
    rust: 'Rust',
    go: 'Go',
    golang: 'Go',
    java: 'Java',
    c: 'C',
    cpp: 'C++',
    'c++': 'C++',
    cs: 'C#',
    csharp: 'C#',
    php: 'PHP',
    swift: 'Swift',
    kotlin: 'Kotlin',
    scala: 'Scala',
    html: 'HTML',
    css: 'CSS',
    scss: 'SCSS',
    sass: 'Sass',
    less: 'Less',
    json: 'JSON',
    yaml: 'YAML',
    yml: 'YAML',
    toml: 'TOML',
    xml: 'XML',
    sql: 'SQL',
    sh: 'Shell',
    bash: 'Bash',
    zsh: 'Zsh',
    fish: 'Fish',
    ps: 'PowerShell',
    powershell: 'PowerShell',
    dockerfile: 'Dockerfile',
    docker: 'Docker',
    md: 'Markdown',
    markdown: 'Markdown',
    txt: 'Plain Text',
    text: 'Plain Text',
    diff: 'Diff',
    git: 'Git',
    vim: 'Vim',
    lua: 'Lua',
    perl: 'Perl',
    r: 'R',
    matlab: 'MATLAB',
    graphql: 'GraphQL',
    nginx: 'Nginx',
    apache: 'Apache',
    ini: 'INI',
    env: 'Environment',
    jsx: 'JSX',
    tsx: 'TSX',
    vue: 'Vue',
    svelte: 'Svelte',
    astro: 'Astro',
    zig: 'Zig',
    nim: 'Nim',
    elixir: 'Elixir',
    erlang: 'Erlang',
    haskell: 'Haskell',
    ocaml: 'OCaml',
    fsharp: 'F#',
    clojure: 'Clojure',
    lisp: 'Lisp',
    scheme: 'Scheme',
    asm: 'Assembly',
    wasm: 'WebAssembly',
    proto: 'Protobuf',
    terraform: 'Terraform',
    hcl: 'HCL'
  };

  function getLanguageName(lang) {
    if (!lang) return null;
    const lower = lang.toLowerCase();
    return languageNames[lower] || lang.toUpperCase();
  }

  async function copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (err) {
      // Fallback for older browsers
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.cssText = 'position:fixed;left:-9999px';
      document.body.appendChild(textarea);
      textarea.select();
      try {
        document.execCommand('copy');
        return true;
      } catch (e) {
        return false;
      } finally {
        document.body.removeChild(textarea);
      }
    }
  }

  function createCopyButton() {
    const button = document.createElement('button');
    button.className = 'copy-button';
    button.setAttribute('aria-label', 'Copy code');
    button.innerHTML = `${icons.copy}<span>Copy</span>`;
    return button;
  }

  function initCodeBlocks() {
    document.querySelectorAll('pre').forEach(pre => {
      const code = pre.querySelector('code');
      if (!code) return;

      // Skip if already initialized
      if (pre.querySelector('.copy-button')) return;

      // Make pre relative for absolute positioning
      pre.style.position = 'relative';

      // Get language from class (e.g., "language-javascript")
      const langClass = Array.from(code.classList).find(c => c.startsWith('language-'));
      if (langClass) {
        const lang = langClass.replace('language-', '');
        pre.setAttribute('data-lang', getLanguageName(lang) || lang);
      }

      // Create copy button
      const copyBtn = createCopyButton();
      pre.appendChild(copyBtn);

      copyBtn.addEventListener('click', async () => {
        const text = code.textContent;
        const success = await copyToClipboard(text);

        if (success) {
          copyBtn.classList.add('copied');
          copyBtn.innerHTML = `${icons.check}<span>Copied!</span>`;

          setTimeout(() => {
            copyBtn.classList.remove('copied');
            copyBtn.innerHTML = `${icons.copy}<span>Copy</span>`;
          }, 2000);
        }
      });
    });
  }

  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initCodeBlocks);
  } else {
    initCodeBlocks();
  }

  // Re-init after Turbo/SPA navigation
  document.addEventListener('turbo:load', initCodeBlocks);
  document.addEventListener('astro:page-load', initCodeBlocks);
})();
