"""Northstar Advisory Group: an entirely fictional advisory firm. Every person, client and project here is invented. Clients and outside
organisations appear only in text and use the reserved `.example` domain (RFC 2606); every address that receives anything is a seeded
person at the demo deployment's own domain (guard.check_addresses). Pure data: no I/O.

Times are offsets from the seed's anchor day (the Monday of the week of the first run, kept in the manifest so a re-run keeps them)."""
from __future__ import annotations

from dataclasses import dataclass

ORG_NAME = "Northstar Advisory Group"
SEED_TAG = "northstar-v1"          # X-OU-Demo header value, Matrix ou.demo.seed, manifest version
UID_PREFIX = "ou-demo-"            # every iCalendar UID, CalDAV href, Matrix alias and message id starts with it


@dataclass(frozen=True)
class Person:
    uid: str
    given: str
    surname: str
    title: str
    department: str
    role: str = "user"             # directory.account.set role: "admin" = organisation admin (org-admin), "user" otherwise

    @property
    def name(self) -> str:
        return f"{self.given} {self.surname}"

    @property
    def initials(self) -> str:
        return (self.given[0] + self.surname[0]).upper()


DEPARTMENTS = ["Leadership", "Advisory", "Finance", "Operations", "Marketing", "People & Culture", "IT"]

PEOPLE: list[Person] = [
    Person("avery.lindqvist", "Avery", "Lindqvist", "Managing Partner", "Leadership"),
    Person("marcus.oyelaran", "Marcus", "Oyelaran", "Partner, Strategy", "Leadership"),
    Person("priya.raghunathan", "Priya", "Raghunathan", "Senior Consultant", "Advisory"),
    Person("tomas.brandvik", "Tomas", "Brandvik", "Consultant", "Advisory"),
    Person("leah.castellano", "Leah", "Castellano", "Consultant", "Advisory"),
    Person("daniel.achterberg", "Daniel", "Achterberg", "Analyst", "Advisory"),
    Person("sofia.marchetti", "Sofia", "Marchetti", "Analyst", "Advisory"),
    Person("hannah.okafor", "Hannah", "Okafor", "Finance Director", "Finance"),
    Person("julian.reyes", "Julian", "Reyes", "Financial Controller", "Finance"),
    Person("mei.holloway", "Mei", "Holloway", "Accounts Specialist", "Finance"),
    Person("owen.fairbrook", "Owen", "Fairbrook", "Operations Manager", "Operations", "admin"),
    Person("grace.abernathy", "Grace", "Abernathy", "Office Coordinator", "Operations"),
    Person("rafael.moreau", "Rafael", "Moreau", "Project Coordinator", "Operations"),
    Person("chloe.whitaker", "Chloe", "Whitaker", "Marketing Lead", "Marketing"),
    Person("ethan.kowalczyk", "Ethan", "Kowalczyk", "Content Strategist", "Marketing"),
    Person("amara.nwosu", "Amara", "Nwosu", "Designer", "Marketing"),
    Person("isabel.duarte", "Isabel", "Duarte", "People & Culture Manager", "People & Culture"),
    Person("noah.petrakis", "Noah", "Petrakis", "Talent Partner", "People & Culture"),
    Person("samuel.adeyemi", "Samuel", "Adeyemi", "IT Lead", "IT", "admin"),
    Person("freya.halvorsen", "Freya", "Halvorsen", "Support Specialist", "IT"),
]
BY_UID = {p.uid: p for p in PEOPLE}

# fictional clients (text only; .example domains, never addressed)
CLIENTS = {
    "brightwater": ("Brightwater Foods", "brightwater.example"),
    "harborview": ("Harborview Health Partners", "harborview.example"),
    "kestrel": ("Kestrel Mobility", "kestrel.example"),
}


# ---------------------------------------------------------------- mail
@dataclass(frozen=True)
class Mail:
    id: str
    sender: str
    to: tuple[str, ...]
    day: int                        # days from the anchor (negative = past)
    hour: int
    body: str
    cc: tuple[str, ...] = ()
    attachments: tuple[str, ...] = ()           # FILES keys
    flagged_by: tuple[str, ...] = ()            # recipients who flag it
    unread_by: tuple[str, ...] = ()             # recipients who have not read it (everyone else: \Seen)


@dataclass(frozen=True)
class Thread:
    id: str
    subject: str
    messages: tuple[Mail, ...]


def _m(id_, sender, to, day, hour, body, **kw) -> Mail:
    return Mail(id_, sender, tuple(to), day, hour, body.strip() + "\n", **{k: tuple(v) for k, v in kw.items()})


ADVISORY = ["priya.raghunathan", "tomas.brandvik", "leah.castellano", "daniel.achterberg", "sofia.marchetti"]
EVERYONE = [p.uid for p in PEOPLE]

THREADS: list[Thread] = [
    Thread("t01", "Brightwater Foods: market entry proposal draft", (
        _m("t01m1", "priya.raghunathan", ["marcus.oyelaran"], -6, 9, """
Hi Marcus,

Attached is the first draft of the Brightwater Foods market entry proposal. Sections 3 (channel options) and 5 (phasing) still need
your input. Could we review it before Thursday's client call?

Best regards,
Priya""", cc=["tomas.brandvik"], attachments=["brightwater-proposal.docx"]),
        _m("t01m2", "marcus.oyelaran", ["priya.raghunathan"], -6, 14, """
Thanks Priya, this reads well. On phasing I would lead with the regional pilot and keep the national rollout as an option.
I have added comments in section 5. Let's take 30 minutes tomorrow morning.

Marcus""", cc=["tomas.brandvik"]),
        _m("t01m3", "tomas.brandvik", ["priya.raghunathan", "marcus.oyelaran"], -5, 10, """
I updated the channel sizing table with the retail panel figures. The revised workbook is attached; the pilot region assumptions
are on the second tab.

Tomas""", attachments=["brightwater-market-model.xlsx"], flagged_by=["priya.raghunathan"]),
    )),
    Thread("t02", "Harborview Health: steering committee pack", (
        _m("t02m1", "leah.castellano", ["avery.lindqvist", "marcus.oyelaran"], -4, 8, """
Good morning,

Please find the steering committee presentation for Harborview Health Partners attached. The operating model options are on
slides 3 and 4. Feedback by Wednesday would let me finalise the pack in time.

Kind regards,
Leah""", cc=["daniel.achterberg"], attachments=["harborview-steering-deck.pptx"], flagged_by=["avery.lindqvist"]),
        _m("t02m2", "avery.lindqvist", ["leah.castellano"], -3, 17, """
Leah, strong pack. Please add one slide on the transition risks and the mitigation we discussed. Otherwise ready to go.

Avery""", cc=["marcus.oyelaran", "daniel.achterberg"]),
    )),
    Thread("t03", "November month-end close", (
        _m("t03m1", "hannah.okafor", ["julian.reyes", "mei.holloway"], -3, 9, """
Hi both,

Month-end close starts Friday. Julian, please confirm the accrual schedule; Mei, the supplier statements reconciliation is due
Monday. The checklist is in the Finance folder.

Thanks,
Hannah"""),
        _m("t03m2", "julian.reyes", ["hannah.okafor"], -3, 11, """
Confirmed. The accruals are in the budget workbook, tab "Accruals". Two open items with the travel agency remain.

Julian""", cc=["mei.holloway"], attachments=["budget-2027.xlsx"]),
        _m("t03m3", "mei.holloway", ["hannah.okafor", "julian.reyes"], -1, 16, """
Supplier statements are reconciled except one invoice from the office cleaning contractor; I have asked them for a copy.

Mei""", unread_by=["hannah.okafor"]),
    )),
    Thread("t04", "Welcome Noah to Northstar", (
        _m("t04m1", "isabel.duarte", EVERYONE, -10, 9, """
Dear colleagues,

Please join me in welcoming Noah Petrakis, who joins People & Culture as our Talent Partner. Noah will lead our graduate
programme and campus partnerships. Say hello in the #general channel!

Isabel"""),
    )),
    Thread("t05", "Laptop refresh: schedule for your team", (
        _m("t05m1", "samuel.adeyemi", ["owen.fairbrook", "grace.abernathy", "rafael.moreau"], -2, 10, """
Hi Owen, Grace and Rafael,

The laptop refresh for Operations is planned for next Tuesday. Each swap takes about 45 minutes; files in Files are kept, local
downloads are not. Freya will book slots with each of you.

Samuel""", cc=["freya.halvorsen"], flagged_by=["owen.fairbrook"]),
        _m("t05m2", "freya.halvorsen", ["grace.abernathy"], -1, 9, """
Hi Grace, would 10:00 on Tuesday work for your swap?

Freya""", unread_by=["grace.abernathy"]),
    )),
    Thread("t06", "Kestrel Mobility: interview notes", (
        _m("t06m1", "daniel.achterberg", ["sofia.marchetti", "priya.raghunathan"], -2, 15, """
Hi Sofia, hi Priya,

I wrote up the six stakeholder interviews from Kestrel Mobility; the summary is attached. The recurring theme is fleet
utilisation reporting. Let's map it against the hypothesis tree tomorrow.

Daniel""", attachments=["kestrel-interview-notes.odt"]),
        _m("t06m2", "sofia.marchetti", ["daniel.achterberg"], -1, 10, """
Great notes. I have started the mapping in the workbook; three interviews point to the same data gap in maintenance planning.

Sofia""", cc=["priya.raghunathan"], unread_by=["daniel.achterberg"]),
    )),
    Thread("t07", "Q1 campaign: case study copy", (
        _m("t07m1", "chloe.whitaker", ["ethan.kowalczyk", "amara.nwosu"], -5, 11, """
Hi team,

For the Q1 campaign we need two case studies (anonymised) and a short thought-leadership piece. Ethan on copy, Amara on the
layout. The brief is attached.

Chloe""", attachments=["q1-campaign-brief.docx"]),
        _m("t07m2", "ethan.kowalczyk", ["chloe.whitaker"], -2, 14, """
First draft of the operating-model case study is in the Marketing folder. I kept all client details generic.

Ethan""", cc=["amara.nwosu"], flagged_by=["chloe.whitaker"]),
    )),
    Thread("t08", "Office move: furniture order", (
        _m("t08m1", "grace.abernathy", ["owen.fairbrook"], -4, 13, """
Hi Owen,

The furniture supplier confirmed delivery for the second floor on the 14th. I need your approval on the revised quote by Friday.

Grace""", flagged_by=["owen.fairbrook"]),
        _m("t08m2", "owen.fairbrook", ["grace.abernathy"], -4, 16, """
Approved, thank you Grace. Please share the floor plan with the team once it is final.

Owen""", cc=["avery.lindqvist"]),
    )),
    Thread("t09", "Graduate programme 2027: shortlist", (
        _m("t09m1", "noah.petrakis", ["isabel.duarte", "marcus.oyelaran"], -1, 11, """
Hi Isabel, hi Marcus,

We have 14 shortlisted candidates for the 2027 graduate programme. Assessment centre dates are proposed in the calendar invitation
I will send shortly.

Noah""", unread_by=["marcus.oyelaran"]),
    )),
    Thread("t10", "Expense policy update", (
        _m("t10m1", "hannah.okafor", EVERYONE, -7, 9, """
Dear all,

From next month expense claims are submitted through the shared Finance workbook template instead of paper forms. The updated
policy is attached. Questions are welcome in the #finance-questions channel.

Hannah Okafor
Finance Director""", attachments=["expense-policy.odt"]),
    )),
    Thread("t11", "Partners' offsite agenda", (
        _m("t11m1", "avery.lindqvist", ["marcus.oyelaran", "hannah.okafor", "owen.fairbrook"], -3, 8, """
Hello,

A first agenda for the partners' offsite is attached: strategy refresh, 2027 hiring plan and the office move. Please add topics
by the end of the week.

Avery""", attachments=["offsite-agenda.odp"], flagged_by=["marcus.oyelaran"]),
    )),
    Thread("t12", "Help desk: shared mailbox access", (
        _m("t12m1", "leah.castellano", ["freya.halvorsen"], -1, 9, """
Hi Freya, I cannot see the project calendar Grace shared yesterday. Could you have a look?

Leah"""),
        _m("t12m2", "freya.halvorsen", ["leah.castellano"], 0, 8, """
Hi Leah, the permissions are in place now. Please reload webmail and it should appear under Shared calendars.

Freya""", unread_by=["leah.castellano"]),
    )),
]


# ---------------------------------------------------------------- calendar
@dataclass(frozen=True)
class Meeting:
    id: str
    organizer: str
    attendees: tuple[str, ...]
    title: str
    day: int
    hour: int
    minutes: int
    location: str = ""
    description: str = ""
    rrule: str = ""
    accepted_by: tuple[str, ...] = ()   # replied in the attendee's own calendar copy; others stay NEEDS-ACTION


def _mt(id_, organizer, attendees, title, day, hour, minutes, **kw) -> Meeting:
    return Meeting(id_, organizer, tuple(attendees), title, day, hour, minutes, **{k: (tuple(v) if isinstance(v, list) else v) for k, v in kw.items()})


MEETINGS: list[Meeting] = [
    _mt("m01", "marcus.oyelaran", ["priya.raghunathan", "tomas.brandvik"], "Brightwater proposal review", 1, 9, 45,
        location="Meeting room Aurora", description="Review sections 3 and 5 before the client call.", accepted_by=["priya.raghunathan"]),
    _mt("m02", "priya.raghunathan", ["marcus.oyelaran", "tomas.brandvik", "leah.castellano"], "Brightwater Foods client call", 3, 14, 60,
        location="Video call", description="Present the draft proposal. Dial-in details are in the Brightwater project folder.",
        accepted_by=["marcus.oyelaran", "tomas.brandvik"]),
    _mt("m03", "leah.castellano", ["avery.lindqvist", "marcus.oyelaran", "daniel.achterberg"], "Harborview steering committee prep", 2, 11, 60,
        location="Meeting room Borealis", accepted_by=["avery.lindqvist", "daniel.achterberg"]),
    _mt("m04", "avery.lindqvist", ADVISORY + ["marcus.oyelaran"], "Advisory weekly stand-up", 0, 9, 30,
        location="Meeting room Aurora", rrule="FREQ=WEEKLY;COUNT=12", accepted_by=ADVISORY),
    _mt("m05", "hannah.okafor", ["julian.reyes", "mei.holloway"], "Month-end close check-in", 4, 10, 30,
        location="Finance corner", accepted_by=["julian.reyes"]),
    _mt("m06", "noah.petrakis", ["isabel.duarte", "marcus.oyelaran", "priya.raghunathan"], "Graduate assessment centre", 9, 9, 240,
        location="Meeting room Borealis", description="Case exercise, group discussion and interviews."),
    _mt("m07", "samuel.adeyemi", ["owen.fairbrook", "freya.halvorsen"], "Laptop refresh planning", 1, 15, 30, accepted_by=["freya.halvorsen"]),
    _mt("m08", "chloe.whitaker", ["ethan.kowalczyk", "amara.nwosu", "marcus.oyelaran"], "Q1 campaign kickoff", 2, 13, 60,
        location="Studio", accepted_by=["ethan.kowalczyk", "amara.nwosu"]),
    _mt("m09", "daniel.achterberg", ["sofia.marchetti", "priya.raghunathan"], "Kestrel hypothesis mapping", -1, 10, 90,
        location="Meeting room Aurora", accepted_by=["sofia.marchetti", "priya.raghunathan"]),
    _mt("m10", "isabel.duarte", ["owen.fairbrook"], "One-to-one", 3, 16, 30, rrule="FREQ=WEEKLY;COUNT=8", accepted_by=["owen.fairbrook"]),
]

# a team calendar Grace keeps (MKCALENDAR in her account; sharing it is a manual step in webmail: docs/admin/demo-organization.md)
TEAM_CALENDAR = {"owner": "grace.abernathy", "slug": UID_PREFIX + "team", "name": "Northstar Team Calendar"}
TEAM_EVENTS: list[Meeting] = [
    _mt("c01", "grace.abernathy", [], "All-hands breakfast", 4, 8, 60, location="Kitchen, 2nd floor"),
    _mt("c02", "grace.abernathy", [], "Office move: second floor", 14, 8, 600, description="Furniture delivery; desks on the 2nd floor are unavailable."),
    _mt("c03", "grace.abernathy", [], "Partners' offsite", 21, 9, 480, location="Lakeside conference centre (fictional)"),
    _mt("c04", "grace.abernathy", [], "Fire drill", 8, 11, 30),
    _mt("c05", "grace.abernathy", [], "Year-end celebration", 25, 18, 180, location="Rooftop terrace"),
    _mt("c06", "grace.abernathy", [], "Quarterly town hall", 11, 15, 60, location="Meeting room Borealis and video"),
]


@dataclass(frozen=True)
class Task:
    id: str
    owner: str
    title: str
    due_day: int
    assigned_by: str = ""
    done: bool = False


TASKS: list[Task] = [
    Task("k01", "tomas.brandvik", "Update channel sizing with the panel data", 2, "priya.raghunathan"),
    Task("k02", "daniel.achterberg", "Add transition risk slide to the steering pack", 1, "leah.castellano"),
    Task("k03", "mei.holloway", "Chase the cleaning contractor invoice copy", 1, "hannah.okafor"),
    Task("k04", "julian.reyes", "Close the two travel agency accrual items", 3, "hannah.okafor"),
    Task("k05", "freya.halvorsen", "Book laptop swap slots for Operations", 0, "samuel.adeyemi", done=True),
    Task("k06", "amara.nwosu", "Layout for the operating-model case study", 5, "chloe.whitaker"),
    Task("k07", "grace.abernathy", "Share the final floor plan", 6, "owen.fairbrook"),
    Task("k08", "noah.petrakis", "Send assessment centre invitations", 2),
    Task("k09", "priya.raghunathan", "Prepare Brightwater call agenda", 2),
    Task("k10", "owen.fairbrook", "Approve the revised furniture quote", -1, done=True),
]


# ---------------------------------------------------------------- files
@dataclass(frozen=True)
class Doc:
    key: str                        # file name, also the attachment key
    kind: str                       # document | spreadsheet | presentation
    title: str
    paragraphs: tuple[str, ...] = ()
    rows: tuple[tuple, ...] = ()    # spreadsheet rows
    slides: tuple[tuple[str, str], ...] = ()   # (title, body)
    comments: tuple[tuple[str, str], ...] = ()  # (author uid, text): ODF annotations / OOXML comments shown by the office editor


FILES: dict[str, Doc] = {d.key: d for d in [
    Doc("brightwater-proposal.docx", "document", "Brightwater Foods: market entry proposal (draft)", (
        "1. Context: Brightwater Foods (fictional) plans to enter the chilled ready-meal segment.",
        "2. Objectives: validate demand, select the channel mix and define a phased entry plan.",
        "3. Channel options: grocery multiples, convenience, direct-to-consumer.",
        "4. Approach: eight weeks in three stages, from discovery to the entry plan.",
        "5. Phasing: regional pilot first; national rollout as an option after twelve months.",
        "6. Team and fees: see the attached schedule."),
        comments=(("marcus.oyelaran", "Lead with the regional pilot here."),)),
    Doc("brightwater-market-model.xlsx", "spreadsheet", "Brightwater market model", rows=(
        ("Channel", "Stores", "Weekly units", "Price", "Annual revenue"),
        ("Grocery multiples", 420, 18, 4.5, "=B2*C2*D2*52"),
        ("Convenience", 310, 9, 4.9, "=B3*C3*D3*52"),
        ("Direct-to-consumer", 1, 650, 5.2, "=B4*C4*D4*52"),
        ("Total", "", "", "", "=SUM(E2:E4)"))),
    Doc("harborview-steering-deck.pptx", "presentation", "Harborview Health Partners: steering committee", slides=(
        ("Harborview Health Partners", "Operating model review: steering committee"),
        ("Where we are", "Discovery complete; 22 interviews; baseline agreed"),
        ("Option A: regional hubs", "Consolidate scheduling into three hubs"),
        ("Option B: networked clinics", "Shared services with local autonomy"),
        ("Next steps", "Decision at the next committee; detailed design in January"))),
    Doc("kestrel-interview-notes.odt", "document", "Kestrel Mobility: stakeholder interview notes", (
        "Six interviews with the operations, maintenance and finance leads of Kestrel Mobility (fictional).",
        "Theme 1: fleet utilisation is reported monthly and too late to act on.",
        "Theme 2: maintenance planning relies on a spreadsheet owned by one person.",
        "Theme 3: finance wants cost per kilometre by vehicle class."),
        comments=(("sofia.marchetti", "Theme 2 matches three interviews; worth a deep dive."),)),
    Doc("kestrel-hypothesis-tree.ods", "spreadsheet", "Kestrel hypothesis tree", rows=(
        ("Hypothesis", "Evidence", "Status"),
        ("Utilisation reporting is too slow", "Interviews 1, 3, 5", "Supported"),
        ("Maintenance planning is a single point of failure", "Interviews 2, 4, 6", "Supported"),
        ("Pricing is below market", "No data yet", "Open"))),
    Doc("budget-2027.xlsx", "spreadsheet", "Budget 2027", rows=(
        ("Cost centre", "Q1", "Q2", "Q3", "Q4", "Total"),
        ("Advisory", 182000, 185000, 188000, 196000, "=SUM(B2:E2)"),
        ("Marketing", 41000, 38000, 36000, 52000, "=SUM(B3:E3)"),
        ("Operations", 64000, 61000, 61000, 63000, "=SUM(B4:E4)"),
        ("IT", 28000, 22000, 22000, 31000, "=SUM(B5:E5)"),
        ("Total", "=SUM(B2:B5)", "=SUM(C2:C5)", "=SUM(D2:D5)", "=SUM(E2:E5)", "=SUM(F2:F5)"))),
    Doc("expense-policy.odt", "document", "Expense policy (effective next month)", (
        "Claims are submitted monthly through the shared Finance workbook template.",
        "Receipts are attached as photos or PDFs; paper forms are no longer accepted.",
        "Travel is booked through the office coordinator; client travel is recharged at cost.")),
    Doc("q1-campaign-brief.docx", "document", "Q1 campaign brief", (
        "Goal: position Northstar as the operating-model specialist for mid-sized organisations.",
        "Deliverables: two anonymised case studies, one thought-leadership article, three social posts.",
        "Timeline: copy by week 3, layout by week 5, launch in week 7."),
        comments=(("chloe.whitaker", "Keep all client details generic."),)),
    Doc("brand-guidelines.odp", "presentation", "Northstar brand guidelines", slides=(
        ("Northstar brand", "How we look and sound"),
        ("Voice", "Clear, calm and practical"),
        ("Colours", "Deep navy, warm white and one accent"))),
    Doc("offsite-agenda.odp", "presentation", "Partners' offsite agenda", slides=(
        ("Partners' offsite", "Agenda draft"),
        ("Strategy refresh", "Where we play, how we win"),
        ("2027 hiring plan", "Advisory growth and graduate programme"),
        ("Office move", "Timeline and budget"))),
    Doc("floor-plan-notes.docx", "document", "Second floor: seating plan notes", (
        "Advisory and Finance move to the second floor; Marketing keeps the studio.",
        "Two quiet rooms and one large meeting room (Borealis) are bookable in the calendar.")),
    Doc("onboarding-checklist.ods", "spreadsheet", "New starter onboarding checklist", rows=(
        ("Step", "Owner", "When"),
        ("Accounts and laptop", "IT", "Day 1"),
        ("Welcome session", "People & Culture", "Day 1"),
        ("Buddy introduction", "Team lead", "Week 1"),
        ("Probation review", "Team lead", "Month 3"))),
]}


@dataclass(frozen=True)
class Folder:
    owner: str
    path: str                       # in the owner's personal space
    files: tuple[str, ...]
    shares: tuple[tuple[str, str], ...] = ()   # (uid, "edit" | "view")


FOLDERS: list[Folder] = [
    Folder("priya.raghunathan", "Projects/Brightwater Foods", ("brightwater-proposal.docx", "brightwater-market-model.xlsx"),
           (("marcus.oyelaran", "edit"), ("tomas.brandvik", "edit"), ("leah.castellano", "view"))),
    Folder("leah.castellano", "Projects/Harborview Health", ("harborview-steering-deck.pptx",),
           (("avery.lindqvist", "view"), ("marcus.oyelaran", "edit"), ("daniel.achterberg", "edit"))),
    Folder("daniel.achterberg", "Projects/Kestrel Mobility", ("kestrel-interview-notes.odt", "kestrel-hypothesis-tree.ods"),
           (("sofia.marchetti", "edit"), ("priya.raghunathan", "edit"))),
    Folder("hannah.okafor", "Finance", ("budget-2027.xlsx", "expense-policy.odt"),
           (("julian.reyes", "edit"), ("mei.holloway", "edit"), ("avery.lindqvist", "view"))),
    Folder("chloe.whitaker", "Marketing", ("q1-campaign-brief.docx", "brand-guidelines.odp"),
           (("ethan.kowalczyk", "edit"), ("amara.nwosu", "edit"))),
    Folder("avery.lindqvist", "Leadership", ("offsite-agenda.odp",), (("marcus.oyelaran", "edit"),)),
    Folder("grace.abernathy", "Office", ("floor-plan-notes.docx",), (("owen.fairbrook", "edit"),)),
    Folder("isabel.duarte", "People & Culture", ("onboarding-checklist.ods",), (("noah.petrakis", "edit"),)),
]


# ---------------------------------------------------------------- chat
@dataclass(frozen=True)
class Room:
    key: str                        # alias local part after UID_PREFIX
    name: str
    creator: str
    members: tuple[str, ...]
    topic: str = ""
    direct: bool = False
    messages: tuple[tuple[str, str], ...] = ()  # (sender uid, text); "@name" mentions are plain text


ROOMS: list[Room] = [
    Room("general", "General", "owen.fairbrook", tuple(EVERYONE), "Company-wide news and questions", messages=(
        ("isabel.duarte", "Please welcome Noah Petrakis to the team!"),
        ("noah.petrakis", "Thank you all, happy to be here."),
        ("grace.abernathy", "Reminder: all-hands breakfast on Friday at 8:00 in the kitchen."),
        ("samuel.adeyemi", "The Wi-Fi in meeting room Aurora was fixed this morning."),
        ("avery.lindqvist", "Great work on the Harborview pack, Leah and Daniel."),
    )),
    Room("announcements", "Announcements", "avery.lindqvist", tuple(EVERYONE), "Official announcements", messages=(
        ("avery.lindqvist", "The office move to the second floor is confirmed for the 14th."),
        ("hannah.okafor", "New expense policy from next month; details in the Finance folder."),
    )),
    Room("brightwater", "Project Brightwater", "priya.raghunathan", ("priya.raghunathan", "marcus.oyelaran", "tomas.brandvik", "leah.castellano"),
         "Brightwater Foods market entry", messages=(
        ("priya.raghunathan", "Draft proposal is in the project folder."),
        ("tomas.brandvik", "Channel sizing updated with the panel data."),
        ("marcus.oyelaran", "Thanks both. Let's lead with the regional pilot."),
        ("leah.castellano", "I can cover the client call notes on Thursday."),
    )),
    Room("harborview", "Project Harborview", "leah.castellano", ("leah.castellano", "avery.lindqvist", "marcus.oyelaran", "daniel.achterberg"),
         "Harborview Health operating model", messages=(
        ("leah.castellano", "Steering pack v2 uploaded."),
        ("daniel.achterberg", "Transition risk slide added as slide 5."),
    )),
    Room("finance-questions", "Finance questions", "hannah.okafor", tuple(EVERYONE), "Expenses, invoices and budgets", messages=(
        ("ethan.kowalczyk", "Can I claim the conference ticket under training?"),
        ("julian.reyes", "Yes, use the training cost code and attach the receipt."),
    )),
    Room("it-help", "IT help", "samuel.adeyemi", tuple(EVERYONE), "Ask the IT team", messages=(
        ("leah.castellano", "The shared calendar does not show up for me."),
        ("freya.halvorsen", "Fixed: permissions are in place, please reload webmail."),
    )),
    Room("dm-priya-tomas", "", "priya.raghunathan", ("priya.raghunathan", "tomas.brandvik"), direct=True, messages=(
        ("priya.raghunathan", "Do you have ten minutes before the client call?"),
        ("tomas.brandvik", "Sure, I'll come to your desk at 13:45."),
    )),
    Room("dm-hannah-julian", "", "hannah.okafor", ("hannah.okafor", "julian.reyes"), direct=True, messages=(
        ("hannah.okafor", "Thanks for closing the accruals so quickly."),
        ("julian.reyes", "Happy to help. Two travel items still open."),
    )),
    Room("dm-grace-owen", "", "grace.abernathy", ("grace.abernathy", "owen.fairbrook"), direct=True, messages=(
        ("grace.abernathy", "Floor plan is final, sharing it now."),
        ("owen.fairbrook", "Perfect, thank you."),
    )),
    Room("dm-chloe-amara", "", "chloe.whitaker", ("chloe.whitaker", "amara.nwosu"), direct=True, messages=(
        ("chloe.whitaker", "Love the case study layout."),
        ("amara.nwosu", "Thanks! I'll send the final PDF tomorrow."),
    )),
]


# ---------------------------------------------------------------- MSP view: further fictional tenants (ICS customers, no deployment)
@dataclass(frozen=True)
class DemoTenant:
    slug: str
    name: str
    contact_name: str
    contact_email: str


MSP_TENANTS: list[DemoTenant] = [
    DemoTenant("demo-harborlane", "Harbor Lane Dental (demo)", "Rosa Lindell", "it@harborlane.example"),
    DemoTenant("demo-copperline", "Copperline Logistics (demo)", "Viktor Hale", "it@copperline.example"),
]
