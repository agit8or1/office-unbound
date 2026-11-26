<!-- Owner brief, received 2026-11-26, verbatim. Audit: docs/design/CONCEPT-ALIGNMENT.md -->

# Office Unbound — Comprehensive UI/UX Concept Alignment and Modernization

## Objective

Bring the actual Office Unbound user interfaces into close alignment with the original interface concepts displayed at:

- https://officeunbound.com
- https://github.com/agit8or1/office-unbound

The goal is to achieve at least 90% visual alignment with the intended design while preserving existing functionality, security, performance, accessibility, and upstream compatibility.

Office Unbound must look and feel like a single professionally designed productivity platform capable of competing with Microsoft 365 and Google Workspace, rather than several independently developed applications sharing a color palette.

Do not simply change colors and logos. Address layout, navigation, typography, spacing, iconography, functionality, responsiveness, interaction patterns, and application integration.

## 1. Conduct a Complete Initial Audit

Before making changes:

- Inspect every current interface concept on officeunbound.com.
- Obtain the original concept assets where available.
- Review the current repository, architecture, implementation, and deployment.
- Review all recent screenshots, especially `docs/screenshots/live-0.13.6/`, or newer versions if available.
- Identify which screenshots represent actual deployments, mocked APIs, test fixtures, or proposed designs.
- Capture fresh screenshots from the latest running deployment.
- Compare each real interface against its corresponding concept.
- Identify missing functionality separately from cosmetic differences.
- Identify reusable components and existing design tokens.
- Identify upstream modifications that could create maintenance problems.

Create `docs/design/CONCEPT-ALIGNMENT.md` containing:

- Concept screenshot
- Current screenshot
- Identified differences
- Visual alignment score
- Functional gaps
- Recommended changes
- Implementation complexity
- Priority
- Acceptance criteria

Do not stop after producing the audit. Continue with implementation.

## 2. Create a Unified Office Unbound Design System

Establish a shared design system across all Office Unbound interfaces.

Use the original website concepts as the primary design reference.

Standardize:

- Primary and secondary colors
- Navy navigation surfaces
- Burnt-orange primary accents
- Teal secondary accents
- Light and dark backgrounds
- Typography
- Font weights
- Heading hierarchy
- Border colors
- Border radii
- Shadows
- Spacing
- Buttons
- Form fields
- Dropdowns
- Dialogs
- Tabs
- Tooltips
- Tables
- Cards
- Notification badges
- Status indicators
- Loading indicators
- Skeleton screens
- Empty states
- Error messages
- Context menus
- Search interfaces

Create centrally managed design tokens using CSS custom properties or another appropriate shared mechanism.

Do not allow individual applications to develop substantially different design languages.

Avoid:

- Excessively large icons
- Oversized cards
- Excessive whitespace
- Unnecessary gradients
- Excessive rounded corners
- Generic AI-generated dashboard aesthetics
- Unnecessary decorative elements
- Inconsistent icon libraries
- Low-contrast text
- Outdated desktop-style toolbars

The design should be professional, modern, information-dense where appropriate, and suitable for daily business use.

## 3. Implement Unified Application Navigation

This is a major priority.

Currently, the portal, Grommunio, OpenCloud, and Element use noticeably different navigation structures.

Implement a consistent Office Unbound application shell wherever technically practical.

Use the original concept's compact application navigation rail as the primary reference.

Include:

- Home
- Mail
- Calendar
- Contacts
- Files
- Documents
- Spreadsheets
- Presentations
- Chat
- Meetings
- Tasks
- Notes
- Additional installed applications
- Settings
- Administration, when authorized

The navigation rail should support:

- Collapsed icon-only mode
- Expanded labeled mode
- Active application highlighting
- Notification badges
- Tooltips
- Keyboard navigation
- User preference persistence
- Responsive mobile behavior

Implement a consistent top navigation bar containing:

- Office Unbound branding
- Current application name
- Global search
- Application launcher
- Notifications
- Help
- User profile
- Appearance preferences
- Account settings

Switching between applications should feel seamless.

Evaluate supported upstream extension points, shared components, reverse-proxy integration, native application adapters, and other maintainable approaches.

Do not introduce insecure iframe workarounds, weaken CSP, bypass authentication, or break SSO to achieve visual consistency.

If a fully shared shell is not technically appropriate for an application, implement a visually consistent equivalent using supported integration methods.

Preserve deep links, browser history, accessibility, and independent application functionality.

## 4. Redesign the User Dashboard

The dashboard should closely resemble the original Office Unbound homepage concept.

Move away from a dashboard that primarily consists of application links and empty cards.

Create an actionable workspace where users can immediately see what requires their attention.

### Personalized Header

Include:

- Time-appropriate greeting
- User's preferred name
- Current date
- Upcoming meeting summary
- Quick actions

Quick actions should include:

- New email
- New calendar event
- New meeting
- New document
- New spreadsheet
- New presentation
- New folder
- Start chat

### Today's Agenda

Display actual authorized calendar data:

- Current time indicator
- Upcoming appointments
- Meeting participants
- Meeting locations
- Online meeting links
- Join meeting button
- Calendar conflicts
- All-day events
- Next meeting countdown

### Needs Your Attention

Create a consolidated actionable feed containing supported items such as:

- Unread priority email
- Flagged email
- Emails requiring follow-up
- Upcoming deadlines
- Document sharing requests
- Document comments
- Chat mentions
- Meeting invitations
- Assigned tasks
- Calendar conflicts

Do not fabricate data or implement misleading placeholder counters.

### Upcoming Meetings

Display:

- Meeting title
- Date and time
- Participants
- Meeting location
- Organizer
- Join button when available

### Recent Activity

Display:

- Recently opened files
- Recently modified documents
- Shared documents
- Recent conversations
- Favorites
- Relevant notifications

### Dashboard Customization

Allow users to:

- Reorder widgets
- Hide optional widgets
- Restore defaults
- Select compact or comfortable density
- Configure supported widget preferences

Persist settings per user.

Use supported APIs and properly scoped permissions to retrieve dashboard data. Do not introduce unrestricted service credentials or cross-tenant data exposure.

## 5. Modernize Email

The current Grommunio-derived interface still looks noticeably older than the original concept.

Modernize it while retaining existing mail capabilities.

Implement or improve:

- Consistent Office Unbound navigation
- Compact folder tree
- Modern compose button
- Refined message list
- Sender avatars or initials
- Message previews
- Attachment indicators
- Unread highlighting
- Flagged messages
- Focused or priority inbox where supported
- Conversation grouping
- Reading pane
- Search and filtering
- Context-sensitive actions
- Responsive layout

Redesign the toolbar:

- Reduce oversized icons.
- Remove unnecessary permanent toolbar clutter.
- Use consistent modern icons.
- Add tooltips.
- Use logical action grouping.
- Move less-common actions into overflow menus.

Improve the compose window:

- Clean recipient selection
- CC/BCC controls
- Attachment management
- Rich-text formatting
- Draft autosave where supported
- Signature selection
- Contact autocomplete
- Clear send action

Do not remove existing advanced mail functionality simply because it is not visible in the mockups.

## 6. Redesign Calendar

The current calendar requires substantial visual improvement.

Correct:

- Poor grid visibility
- Missing or insufficiently visible day boundaries
- Excessive whitespace
- Weak date headers
- Outdated toolbar styling
- Inconsistent iconography
- Poor visual hierarchy
- Dark-mode inconsistencies

Provide modern views:

- Day
- Work week
- Week
- Month
- Agenda

Include:

- Clearly defined day columns
- Readable time labels
- Current time indicator
- Today highlighting
- Color-coded calendars
- Event blocks
- Event previews
- All-day event area
- Calendar visibility controls
- Shared calendars
- Meeting invitations
- Quick event creation

Where supported, implement drag-and-drop rescheduling and event resizing.

Improve event creation and editing dialogs.

Calendar must remain readable at common desktop resolutions, on tablets, and on mobile browsers.

Validate the calendar using a realistic populated schedule, not just an empty account.

## 7. Modernize Files and File Sharing

Align OpenCloud's appearance more closely with the Office Unbound concept.

Retain its underlying functionality while improving:

- Navigation consistency
- File and folder icons
- Breadcrumb navigation
- Search
- Sorting
- Filtering
- File list density
- Grid and list views
- File preview
- Context menus
- Sharing dialogs
- Permission management
- Recent files
- Favorites
- Shared with me
- Shared by me
- Deleted files
- File activity
- Upload progress
- Drag-and-drop behavior

Display relevant metadata:

- File name
- File type
- Size
- Modified date
- Owner
- Sharing status

Ensure file and folder sharing interfaces are understandable to nontechnical business users.

Review the search field for contrast issues and improve the overall empty-state presentation.

Do not compromise existing file synchronization, WebDAV, permissions, versioning, or sharing functionality.

## 8. Documents, Spreadsheets and Presentations

Make the online editing experience feel like part of Office Unbound.

Review the existing document editor integration and supported customization methods.

Where practical:

- Apply Office Unbound branding.
- Standardize document headers.
- Display document names consistently.
- Provide clear save status.
- Provide sharing controls.
- Show collaboration participants.
- Provide consistent return-to-files navigation.
- Maintain familiar editing controls.
- Improve loading and error screens.
- Ensure coherent light and dark appearance.

Create polished interfaces for:

- Document creation
- Spreadsheet creation
- Presentation creation
- Template selection
- Recent documents
- Shared documents
- Document opening
- Collaboration

Preserve editor functionality, document compatibility, collaborative editing, autosave, and supported upstream upgrades.

Do not introduce unsupported editor modifications solely to match a concept image.

## 9. Chat and Collaboration

The current chat application still feels primarily like Element.

Bring it closer to the Office Unbound design language while preserving Matrix functionality and encryption.

Improve:

- Application navigation
- Room and channel list
- Direct message list
- Conversation layout
- Message composer
- User avatars
- Presence indicators
- Unread indicators
- Mentions
- Message reactions
- Thread presentation
- File sharing
- Search
- Settings
- Empty states

Where supported, organize navigation into understandable business categories:

- Direct messages
- Teams
- Channels
- Groups
- Favorites
- Unread conversations

Improve branding throughout:

- Initial welcome screen
- Encryption onboarding
- Identity verification
- Recovery key dialogs
- Consent screens
- Error messages
- Authentication transitions

Do not weaken or bypass end-to-end encryption, cross-signing, identity verification, or recovery-key protections.

Explain security-related actions clearly in language ordinary business users can understand.

## 10. Meetings and Video Conferencing

Review the current meeting implementation and roadmap.

Bring implemented meeting interfaces into alignment with Office Unbound's concepts.

Where functionality exists, provide:

- Schedule meeting
- Start instant meeting
- Join meeting
- Upcoming meetings
- Participant list
- Microphone and camera selection
- Screen sharing
- Meeting chat
- Meeting controls
- Device testing
- Meeting settings

Ensure users can reach meetings consistently from:

- Dashboard
- Calendar
- Chat
- Application launcher

Do not present planned functionality as operational.

Document missing capabilities and implement those that can be completed safely within the current architecture.

## 11. Global Search

The original concept presents global search as a unified productivity feature.

Evaluate and implement a permission-aware search interface that can progressively search:

- Email
- Contacts
- Calendar events
- Files
- Documents
- Chat messages
- Tasks

Include:

- Categorized results
- Search suggestions where supported
- Keyboard shortcuts
- Recent searches
- Filters
- Result previews
- Deep links to the source application

Search must respect tenant boundaries, user permissions, document sharing restrictions, and chat encryption.

If certain content cannot be searched safely, explicitly indicate that limitation.

Never bypass end-to-end encryption or access controls to provide global search.

## 12. Organization Administration

Compare the real Organization Admin interface against the website's Organization Admin concept.

Improve its design and usability for business administrators.

Review and align:

- Organization overview
- Users
- Groups
- Roles and permissions
- Domains
- Mail configuration
- Shared resources
- File sharing policies
- Authentication
- MFA
- Security settings
- Audit logs
- Storage usage
- Service health
- Organization settings
- Branding
- User onboarding

Provide clear descriptions and guided workflows for common administrative tasks.

Preserve strict role-based access controls.

Do not expose MSP or infrastructure-level controls to ordinary organization administrators.

## 13. MSP Control Center

Compare the actual MSP interface against the original website concepts.

Create a professional multi-tenant management experience with:

- Customer overview
- Organization management
- Tenant health
- User counts
- Storage consumption
- Service status
- Alerts
- Provisioning
- Subscription or service-plan information where implemented
- Deployment status
- Backup status
- Update status
- Security indicators

Use compact, useful tables and dashboards.

Include:

- Tenant search
- Filters
- Sorting
- Tenant-specific navigation
- Clearly visible tenant context
- Role-based access
- Audited administrative actions

Make it visually distinct from the end-user portal while retaining the same design system.

Never allow cross-tenant information leakage.

## 14. Infrastructure Control Server

Review the ICS console and compare it to the website's infrastructure concepts.

Improve:

- Infrastructure overview
- Proxmox clusters
- Hosts
- Virtual machines
- Containers
- Provider connections
- Service health
- Resource consumption
- Storage
- Networking
- Certificates
- Backup status
- Deployment jobs
- Update management
- Rollback workflows
- Incidents
- Alerts

Use meaningful visualizations rather than generic decorative charts.

Prioritize:

- Actionable alerts
- Capacity warnings
- Failed deployments
- Degraded services
- Resource exhaustion
- Pending approvals
- Infrastructure health

Maintain existing approval gates and safeguards.

Keep the audit log on its dedicated page rather than unnecessarily occupying dashboard space.

Do not confuse the ICS infrastructure control plane with end-user identity or application management.

## 15. Migration Center

Align the Migration Center with the original planned design.

Review supported workflows:

- Source discovery
- Source connectivity
- User mapping
- Domain mapping
- Mail migration
- Calendar migration
- Contact migration
- File migration
- Dry runs
- Migration readiness
- Staged coexistence
- Progress monitoring
- Error reporting
- Cutover
- Verification
- Rollback

Provide intuitive wizard-based workflows with:

- Clear progress indicators
- Explanations
- Validation
- Warning states
- Approval checkpoints
- Detailed error messages
- Downloadable reports where supported

Clearly distinguish implemented migration functionality from planned features.

## 16. Mobile and Desktop Consistency

All browser interfaces must be responsive.

Test at minimum:

- 1920 × 1080
- 1600 × 900
- 1440 × 900
- 1366 × 768
- 1024 × 768
- 768 × 1024
- 390 × 844
- 360 × 800

Check:

- Horizontal overflow
- Navigation behavior
- Touch targets
- Dialog sizing
- Tables
- Form inputs
- Font readability
- Dropdowns
- Scrolling
- Keyboard behavior

Coordinate the design system with the Windows desktop application under development.

Ensure future macOS, Linux, iOS, and Android applications can consume compatible design tokens and interaction patterns.

Do not claim native application functionality that has not been implemented.

## 17. Dark Mode

Implement consistent appearance settings:

- System
- Light
- Dark

Persist the user's preference and synchronize it across applications where technically supported.

Correct known issues including:

- Inconsistent navy and warm-gray surfaces
- White flashes during loading
- Poor contrast
- Unstyled authentication screens
- Inconsistent dialogs
- Unreadable input fields
- Incorrect icon colors
- Third-party default backgrounds
- Calendar grid visibility

Ensure dark mode is intentionally designed, not simply inverted.

Target WCAG 2.2 AA accessibility.

## 18. Create a Realistic Demonstration Organization

Create a dedicated, isolated demonstration environment containing entirely fictional business data.

Suggested organization: Northstar Advisory Group.

Include:

- Approximately 15–25 employees
- Multiple departments
- User avatars or initials
- Active inboxes
- Email threads
- Attachments
- Flagged messages
- Meeting invitations
- Shared calendars
- Upcoming appointments
- Documents
- Spreadsheets
- Presentations
- Shared project folders
- File permissions
- Chat channels
- Direct messages
- Document comments
- Assigned tasks where supported
- Notifications
- Multiple demonstration tenants for MSP views

Create a repeatable, idempotent demo-data seeding mechanism.

Requirements:

- No real customer data
- No real credentials in the repository
- No external email delivery
- No unintended external invitations
- No production data modification
- Explicit demo-environment safeguards
- Clear separation from operational deployments

The demo environment must use real application functionality and APIs.

Do not fake functionality by injecting static UI elements or fabricated API responses into screenshots advertised as real.

## 19. Performance and Accessibility

Visual improvements must not introduce significant performance regressions.

Measure before and after:

- Initial page load
- Application navigation
- Time to interactive
- Dashboard API latency
- Search latency
- Browser memory consumption
- JavaScript bundle sizes where applicable

Use:

- Lazy loading
- Efficient API requests
- Pagination
- Appropriate caching
- Optimized assets
- Accessible semantic markup

Verify:

- Keyboard navigation
- Visible focus states
- Screen reader compatibility
- Color contrast
- Reduced-motion preferences
- Accessible dialogs
- Form labels
- Error announcements

Do not sacrifice usability or performance merely to reproduce a decorative design element.

## 20. Upstream Compatibility and Security

Maintain a clean separation between Office Unbound's own code and upstream application modifications.

Prefer:

1. Supported configuration
2. Supported themes
3. Supported plugins and extensions
4. Shared Office Unbound components
5. Maintainable adapters
6. Minimal, documented upstream patches only when necessary

Maintain an inventory of upstream modifications.

Document:

- Why each modification is necessary
- Upstream version compatibility
- Upgrade considerations
- Automated tests
- Rollback procedures
- Relevant license obligations

Do not weaken:

- Authentication
- Authorization
- SSO
- MFA
- CSRF protections
- CSP
- Certificate verification
- Tenant isolation
- Encryption
- API authentication
- Session security
- Audit logging

Run security regression tests following changes.

## 21. Automated Visual Regression Testing

Implement or expand automated screenshot capture using Playwright or the existing testing framework.

Capture each major interface in:

- Light mode
- Dark mode
- Desktop
- Tablet
- Mobile
- Populated state
- Empty state
- Relevant error states

Use stable test fixtures for repeatable visual regression tests.

Separately capture authenticated screenshots from the actual running deployment.

Detect:

- Layout regressions
- Horizontal overflow
- Clipped content
- Broken icons
- Unexpected scrollbars
- Missing elements
- Contrast issues
- Inconsistent theme application

Create a screenshot manifest containing:

- Application
- Screen name
- Version
- Git commit
- Capture date
- Viewport
- Theme
- Evidence type
- Deployment or fixture source
- Known limitations

Never misrepresent mocked screenshots as live deployment evidence.

## 22. Side-by-Side Concept Comparison

Create an internal design comparison report containing:

- Original website mockup
- Previous real screenshot
- Updated real screenshot
- Visual alignment score
- Functional alignment score
- Remaining differences
- Explanation for intentional deviations

Score each interface independently.

Suggested visual scoring weights:

- Layout and structure: 25%
- Navigation: 20%
- Color and branding: 15%
- Typography and spacing: 15%
- Components and iconography: 10%
- Responsive behavior: 10%
- Visual polish: 5%

Evaluate functional alignment separately.

Do not award full functional credit to nonworking buttons, placeholders, mock APIs, or planned features.

Target 90% or greater visual alignment where technically practical.

Any substantial intentional deviation from the original concept must be documented and justified.

## 23. Public Website Screenshot Updates

Once updated interfaces are deployed and verified, prepare the real screenshots for use on officeunbound.com.

Separate website images into:

- Available in Alpha — actual running functionality
- In Development — partially implemented interfaces
- Planned Interface — design concepts

Use populated real application screenshots wherever possible.

Replace concept screenshots when the real implementation provides a sufficiently polished and accurate representation of the intended experience.

Do not misrepresent release status or imply production readiness.

If the website source is maintained in a separate repository, prepare the assets and precise integration instructions rather than modifying an unrelated deployment without authorization.

## 24. Implementation Priorities

### P0 — Immediate

- Complete concept-versus-real audit.
- Establish shared design tokens.
- Correct calendar rendering and visibility.
- Improve email toolbar and layout.
- Establish unified application navigation.
- Correct theme inconsistencies.
- Create realistic demo data.
- Capture baseline screenshots.

### P1 — Core Experience

- Implement actionable dashboard widgets.
- Improve email and calendar integration.
- Refine Files UI.
- Modernize Chat UI.
- Improve global search where safely supported.
- Improve mobile responsiveness.
- Capture updated live screenshots.

### P2 — Administrative Experience

- Organization Admin alignment.
- MSP Control Center alignment.
- ICS alignment.
- Migration Center alignment.
- Administrative workflow usability improvements.

### P3 — Final Polish

- Documents, spreadsheets, and presentations.
- Meeting interface consistency.
- Desktop application design coordination.
- Accessibility refinements.
- Visual regression automation.
- Website screenshot preparation.
- Final performance and security validation.

## 25. Working Instructions

You are authorized to analyze, plan, and implement these improvements within the Office Unbound development environment.

- Inspect existing code before making architectural decisions.
- Reuse existing functionality wherever possible.
- Do not unnecessarily rewrite working components.
- Implement in manageable, independently testable phases.
- Commit logical changes separately.
- Preserve existing functionality.
- Run existing tests and add new tests.
- Update relevant documentation.
- Update ROADMAP.md and applicable progress tracking.
- Keep screenshots current.
- Document blockers and unresolved issues.
- Do not deploy unverified changes to production.
- Do not falsely mark features complete.
- Do not hide functional gaps with cosmetic placeholders.
- Do not remove functionality merely to simplify the UI.
- Do not stop after creating a plan.

Use specialized agents where available for frontend development, upstream integration, security, accessibility, testing, and visual design. Coordinate their work around one shared design system.

## 26. Final Deliverables

At completion, provide:

1. Original versus updated visual comparison.
2. Per-application visual alignment scores.
3. Separate functional alignment scores.
4. List of implemented improvements.
5. List of remaining gaps.
6. Updated real deployment screenshots.
7. Updated light and dark mode screenshots.
8. Mobile and desktop screenshots.
9. Automated test results.
10. Security regression results.
11. Performance comparison.
12. Upstream modification inventory.
13. Updated roadmap and documentation.
14. Website-ready screenshot assets.
15. Git commit references.
16. Deployment and rollback instructions.

The end result should be a polished, cohesive, recognizable Office Unbound platform.

A user switching from Mail to Calendar to Files to Chat should feel that they are switching between modules of the same product, not being redirected to four unrelated applications.

Begin the audit and implementation now.
