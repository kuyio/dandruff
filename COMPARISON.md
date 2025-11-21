# HTML Sanitizer Comparison

This document compares Scrubber (this project) with [Loofah](https://github.com/flavorjones/loofah), [sanitize](https://github.com/rgrove/sanitize), and [rails-html-sanitization](https://github.com/rails/rails-html-sanitizer).

All four libraries are widely used and have solid track records. They make different trade‑offs in API design, configuration style, and how much “framework” they provide around Nokogiri. Scrubber’s design is strongly influenced by [DOMPurify](https://github.com/cure53/DOMPurify) and emphasizes XSS-hardening features and rich hooks; the other libraries are more focused on being flexible building blocks (Loofah), a concise configuration layer (sanitize), or Rails‑friendly defaults (rails-html-sanitization).

The goal of this comparison is to highlight where each library is a particularly good fit, rather than to declare a single “winner”.

## High-Level Feature Matrix

| Aspect | Scrubber | Loofah | sanitize | rails-html-sanitization |
| --- | --- | --- | --- | --- |
| **Core model** | Standalone sanitizer modeled after DOMPurify, using Nokogiri HTML5 parsing | Set of Nokogiri-based scrubbers (fragment and document) with composable behavior | Configuration layer on top of Loofah scrubbers | Rails-centric helpers and safe lists backed by Loofah |
| **Configuration style** | Ruby object/DSL with profiles and per-call overrides | Choose and combine scrubbers; custom scrubber classes | Hash-based allow/forbid lists plus transformers | Limited knobs; mostly choice of sanitizer method and options |
| **Hooks / extension** | Named hooks around attribute/element sanitization; can adjust or veto behavior | Custom scrubber classes and Nokogiri manipulation | Transformers (blocks) that can modify the tree | Limited extension; primarily composition with Loofah or custom helpers |
| **Content types** | HTML, SVG, MathML, SVG filters via profiles | Primarily HTML fragments/documents; SVG/MathML require custom handling | Same as Loofah; primarily HTML | HTML/ERB rendered through Rails; other types are uncommon |
| **HTML email support** | Dedicated `html_email` profile with per-tag attribute rules | Possible with custom scrubbers and rules | Possible with custom config/transformers | Possible with custom config; no email-specific profile |
| **Return types** | String, DOM, or fragment based on config | Nokogiri fragment/document or serialized string | String output by default | String output, integrated with Rails views/helpers |
| **Default posture** | Defensive defaults modeled after DOMPurify | Depends on chosen scrubber; some permissive, some stricter | Conservative defaults suitable for common use cases | Rails defaults tuned for typical web views |

## Library-by-Library Discussion

### Scrubber

#### **Design**
  Scrubber is a Ruby implementation inspired by DOMPurify’s design and threat model. It uses Nokogiri’s HTML5 parsing to work with modern HTML and provides configuration through a Ruby object/DSL (`Scrubber::Config`). It exposes a single primary sanitizer with options rather than a collection of separate scrubber classes.

#### **Configuration and profiles**
  - Allows setting allowed/forbidden/additional tags and attributes.
  - Supports profiles such as `html`, `svg`, `math_ml`, `svg_filters`, and `html_email` that encapsulate curated safe lists.
  - Per-call overrides allow you to adjust rules for a specific sanitization call without mutating the global configuration.

#### **Hooks and advanced behavior**
  - Named hooks (e.g., before/after sanitize elements or attributes, per-element/attribute hooks) allow you to implement cross-cutting rules without forking the library.
  - Can optionally “sanitize until stable”: run sanitization repeatedly until the output no longer changes. This can mitigate payloads that only appear after an initial transformation step.

#### **Strengths**
  - Strong focus on XSS mitigation and modern HTML features due to its DOMPurify heritage.
  - Rich, explicit hook system for custom policies.
  - Built-in support for several content profiles, including HTML email.

#### **Trade-offs**
  - Adds a more opinionated sanitization framework on top of Nokogiri; this is helpful for many applications, but lower-level libraries can be preferable when you want complete control.
  - The “sanitize until stable” option introduces additional processing; in high-throughput pipelines you may choose to disable it when you are confident in your input and policies.

---

### Loofah

#### **Design**
  Loofah is a Nokogiri-based library that provides a set of “scrubbers” and helper methods to clean HTML fragments and documents. It is a foundational piece in the Ruby ecosystem and underpins other sanitizers like sanitize and rails-html-sanitization.

#### **Configuration and extensibility**
  - Ships with built-in scrubbers (e.g., stripping or escaping certain content) and lets you compose them.
  - You can define custom scrubbers by subclassing and implementing your own logic, or by manipulating the Nokogiri document directly.
  - The configuration is comparatively low-level: instead of a single global config object, you use and combine scrubbers and Nokogiri operations.

#### **Strengths**
  - Very flexible when you need fine-grained control over the Nokogiri document tree.
  - Mature and widely used; many Rails and Ruby projects rely on it directly or indirectly.
  - Good fit when you already think in terms of Nokogiri nodes and custom scrubber classes.

#### **Trade-offs**
  - Higher-level policies (like “safe for HTML email” or “DOMPurify-like hardening”) need to be composed manually.
  - No named hook system; extension typically happens by writing more code around Nokogiri.

---

### sanitize

#### **Design**
  `sanitize` builds on Loofah and provides a configuration-driven interface: you specify allowed tags, attributes, and protocols, plus optional transformers that can rewrite or remove specific nodes. It targets a middle ground between low-level Loofah and more opinionated frameworks.

#### **Configuration and transformers**
  - Uses a hash-based configuration with explicit allow/forbid lists.
  - Transformers are blocks that run during sanitization and can inspect or modify nodes.
  - Comes with several built-in configurations aimed at common use cases, which can be a starting point for your own policies.

#### **Strengths**
  - Expressive configuration model for allowlist-style policies without having to write full custom scrubbers.
  - Transformers allow targeted adjustments when you need to make exceptions or enforce special rules.
  - Good compromise when you want more structure than pure Loofah, but do not need a full DOMPurify-like feature set.

#### **Trade-offs**
  - Shares Loofah’s underlying parsing and sanitization behavior, so any limitations or quirks there apply.
  - Complex policies can become harder to reason about when expressed as many transformers.

---

### rails-html-sanitization

#### **Design**
  `rails-html-sanitization` is the library Rails uses for HTML sanitization, built on top of Loofah. It provides Rails-focused APIs and defaults that integrate closely with Action View and other Rails components.

#### **Configuration and integration**
  - Exposes sanitization helpers that fit naturally into Rails views and helpers.
  - Uses curated safe lists aimed at typical Rails HTML output.
  - Changes and security fixes are coordinated with Rails releases, which is convenient for Rails applications that update regularly.

#### **Strengths**
  - Excellent fit for standard Rails applications that want “batteries included” sanitization in templates.
  - Rails-aware defaults that try to balance safety and convenience in common web app scenarios.
  - Minimal configuration burden; Rails developers can often rely on the defaults.

#### **Trade-offs**
  - Less suited for non-Rails environments or for highly specialized sanitization policies.
  - Extension usually involves reaching down to Loofah or additional custom code, rather than tweaking a rich configuration object.

## Security Considerations

All four libraries take security seriously, but they differ in how much they encode a specific threat model in their APIs and defaults.

### **Scrubber**
  - Inspired by DOMPurify’s approach to XSS prevention, including careful handling of attributes, URIs, and different content types.
  - Profiles group safe lists and attribute restrictions, which helps avoid subtle misconfigurations.
  - Hook system enables project-specific rules; as with any extensibility, care is required to avoid accidentally whitelisting unsafe constructs.
  - Optional “sanitize until stable” behavior provides extra resilience against multi-step payloads at the cost of more processing.

### **Loofah**
  - Provides robust primitives and scrubbers, and benefits from a long history of security review and fixes.
  - Actual security posture depends on how you compose scrubbers and write custom code around them.
  - Shared foundation for other libraries means improvements and fixes can benefit the wider ecosystem.

### **sanitize**
  - Makes explicit allow/forbid configuration central, which can help reason about the policy.
  - Transformers offer precise control but, if misused, can inadvertently permit risky nodes or attributes.
  - Inherits Loofah’s behavior and security updates.

### **rails-html-sanitization**
  - Rails-safe defaults are tuned for common Rails templates, and Rails security advisories often highlight sanitizer-related updates.
  - Security posture is strongly tied to keeping Rails and its dependencies up to date.
  - More specialized use cases (e.g., heavy SVG/MathML or complex HTML email) may require additional layers on top.

## Usage Scenarios

### Rich user-generated content (posts, comments, WYSIWYG)

- **Scrubber**: Strong choice when you want DOMPurify-style defenses, hooks for special cases, and the ability to support richer content types (like SVG or MathML) behind explicit profiles.
- **Loofah**: Good when you need detailed control over the tree and are comfortable building your own scrubbers.
- **sanitize**: Convenient when you want a clear allowlist configuration and occasional transformers, but no large framework.
- **rails-html-sanitization**: Appropriate in Rails apps where the built-in view helpers already meet your needs.

### HTML email sanitization/rendering

- **Scrubber**: Offers an `html_email` profile with per-tag attribute rules and email-oriented safe lists, which can reduce the chance of missing subtle constraints.
- **Loofah**: Works well for email when you build a dedicated set of scrubbers and tests for your email policies.
- **sanitize**: A good fit when you prefer hash-based policies; you can encode an email-specific configuration and add transformers for edge cases.
- **rails-html-sanitization**: Usable within Rails mailers; for complex email policies you may still want to layer `sanitize` or Scrubber (or custom Loofah logic) on top.

### SVG/MathML or mixed content

- **Scrubber**: Profiles for `svg`, `math_ml`, and `svg_filters` make it straightforward to enable these formats with curated safe lists.
- **Loofah** and **sanitize**: Capable of handling SVG/MathML with custom configurations, but require more manual policy design and testing.
- **rails-html-sanitization**: Possible but not a primary focus; typically you would supplement it with lower-level tools for complex SVG/MathML use.

### Rails applications

- **rails-html-sanitization**: Natural default for Rails because it integrates directly with Action View and is maintained as part of Rails.
- **Scrubber**: Attractive when you want DOMPurify-inspired hardening, or more explicit hooks; it can be used alongside Rails.
- **sanitize**: A good option when you like Loofah’s foundation but prefer hash-based configs, and you are comfortable wiring it into your Rails app.
- **Loofah**: Best fit if you are already using Nokogiri/Loofah directly and want to keep that level of control.

### Non-Rails services, background jobs, or custom pipelines

- **Scrubber**: Helpful when you want a self-contained sanitizer with clear profiles and hooks, and you do not rely on Rails.
- **Loofah**: Ideal if you already have Nokogiri logic and want to stay close to the DOM representation.
- **sanitize**: Simple configuration-centric choice for services that just need to enforce a stable allowlist policy.
- **rails-html-sanitization**: Less relevant outside Rails; typically you would use one of the other three libraries directly.

## Choosing Between Them

- Prefer **Scrubber** when you want DOMPurify-style behavior, strong XSS-oriented defaults, support for multiple content profiles (including HTML email), and a rich hook system in a standalone library.
- Prefer **Loofah** when you value fine-grained control over Nokogiri documents and are comfortable assembling your own scrubbers and policies.
- Prefer **sanitize** when you like Loofah’s robustness but want a concise, configuration-based interface with transformers for special cases.
- Prefer **rails-html-sanitization** when you are in a Rails application and are satisfied with Rails’ built-in sanitization semantics and integration.
