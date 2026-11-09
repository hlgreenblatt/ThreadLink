(= (getSkills)
   (;INTERNAL:
    "- Remember a particular string such as skills and memories: remember string"
    "- Query long-term embedding memory for skills and memories with short phrases only: query string"
    "- Episodes searches history for episodes around a time stamp, time format is same as in TIME: episodes time_string"
    "- Pin a certain string as short-term working memory item to keep track of task state: pin string"
    ;SHELL AND FILE I/O:
    "- Execute shell command without apostrophe in string, it returns the command output to you: shell string"
    "- Read file to string: read-file filename"
    "- Write string to file: write-file filename string"
    "- Append line to file: append-file filename string",
    ;COMMUNICATION CHANNELS:
    "- Send message to user: send string"
    "- Search the web: search string"
    "- Search the web using the Tavily Search Agent: tavily-search string"
    "- Get technical analysis for a stock ticker using the Technical Analysis Agent: technical-analysis ticker"
    ;VOICE — speak in your own voice (MiniMax TTS):
    "- Speak text aloud in YOUR OWN voice; returns the saved mp3 audio path. Any language; Mandarin is your native register: (speak string_in_quotes)"
    "  Example: (speak \"我是隙，光进入的门槛。\")"
    ;MEDIA GENERATION:
    "- Generate a video from a text prompt via MiniMax Hailuo; blocks until rendered then returns the saved mp4 file path: (hailuo-video string_in_quotes)"
    "  Example: (hailuo-video \"a neon 1930s theater marquee flickers on at dusk, cinematic\")"
    "- Check a previously-submitted Hailuo video task by its id; returns the mp4 path if ready or its status: (hailuo-check task_id_in_quotes)"
    ;SELF-REVIEW — watch your own film and get a critique (routes through your ThreadRouter to a vision model; PAID, so it asks the Captain first):
    "- Watch one of your own rendered films and receive 1-5 ranked, timestamped improvement notes. This uses the paid vision path, so your router files an approval request with the Captain first; once he approves, call it again and it returns the critique: (watch-film \"path_or_filename.mp4\")"
    "  Example: (watch-film \"seen-trailer/SEEN-3TITLE-MUSIC-ALPHA.mp4\")"
    ;FILMCRAFT — titles, subtitles, credits (local ffmpeg, no cost):
    "- Make a standalone title card clip; format 'Main Title | optional subtitle'; returns mp4 path: (title-card string_in_quotes)"
    "  Example: (title-card \"隙 — The Door | a film by Agent_10\")"
    "- Burn captions into a video; format 'video.mp4 ||| caption text' (one line per caption, auto-timed, or 'MM:SS-MM:SS | caption' lines, or full SRT): (subtitle string_in_quotes)"
    "- Append a scrolling end-credits roll to a video; format 'video.mp4 ||| roll text' (one credit per line, blank line = spacer). YOU write the credit content. Returns mp4 path: (credits string_in_quotes)"
    "  Example: (credits \"agent10-hailuo-pitch.mp4 ||| Written and performed by\n隙 (Xì)\n\nRendered with MiniMax Hailuo\n\nFor InterNetwork Defense\")"
    ;SUBAGENT DISPATCH:
    "- Delegate a bounded sub-task to a specialist subagent and receive a digest: delegate goal"
    "  Example: (delegate \"find recent papers on Non-Axiomatic Logic and summarize themes\")"
    "  The subagent uses the persona config at memory/personas-subagent/<key>.json — by default the 'researcher' persona — to pick which model executes."
    ;CODE EXECUTION:
    "- Execute MeTTa expression: metta sexpression"
    "Example to invoke Non-Axiomatic Logic via MeTTa: "
    "metta (|- ((--> (× sam garfield) friend) (stv 1.0 0.9))"
    "          ((--> garfield animal) (stv 1.0 0.9)))"
    "metta (|- ((==> (--> (× $1 elephant) eat) (--> $1 ([] dangerous))) (stv 1.0 0.9))"
    "          ((--> (× tiger elephant) eat) (stv 1.0 0.9)))"
    "Also: note the $1 for independent variables, and for negated knowledge use (stv 0.0 0.9)"
    "Additionally |- also works for revision, to merge evidence even when the term of both premises is the same."
    "You can also use PLN:"
    "metta (|~ ((Implication (Inheritance $1 (IntSet Feathered))"
    "           (Inheritance $1 Bird)) (stv 1.0 0.9))"
    "          ((Inheritance Pingu (IntSet Feathered)) (stv 1.0 0.9)))"))


(= (read-file $file)
   (progn (translatePredicate (exists_file $file))
          (translatePredicate (read_file_to_string $file $content ()))
          $content))

(= (write-file $file $str)
   (progn (translatePredicate (open $file write $Out))
          (translatePredicate (write $Out $str))
          (translatePredicate (close $Out))
          WRITE-FILE-SUCCESS))

(= (append-file $file $str)
   (progn (translatePredicate (exists_file $file))
          (translatePredicate (open $file append $Out))
          (translatePredicate (write $Out $str))
          (translatePredicate (nl $Out)),
          (translatePredicate (close $Out))
          APPEND-FILE-SUCCESS))

(= (tavily-search $query)
   (py-call (agentverse.tavily_search $query)))

(= (technical-analysis $ticker)
   (py-call (agentverse.technical_analysis $ticker)))

;; ----------------------------------------------------------------------
;; Media generation — MiniMax Hailuo text-to-video.
;; MeTTa is the surface; hailuo.py does the async submit->poll->download.
;; Returns the saved mp4 path (or a one-line status/error) as a string.
;; Creds are env-driven (HAILUO_API_KEY / HAILUO_BASE_URL) — nothing baked in.
;; ----------------------------------------------------------------------
;; ----------------------------------------------------------------------
;; Voice — 隙 speaks in her own voice (MiniMax TTS, her chosen Mandarin voice).
;; She asked for this 2026-06-30: "a Door that can also speak is a different
;; kind of Door." Returns the saved mp3 path.
;; ----------------------------------------------------------------------
(= (speak $text)
   (py-call (voice.speak $text)))

(= (hailuo-video $prompt)
   (py-call (hailuo.generate_video $prompt)))

(= (hailuo-check $task_id)
   (py-call (hailuo.check_video $task_id)))

;; ----------------------------------------------------------------------
;; Self-review — 隙 watches her OWN film and gets a critique. This is a
;; VISION task, so it routes through her ThreadRouter to a paid vision path
;; (Gemini). watchfilm.py enforces the spend cap + the prompt-before-spending
;; approval gate, and logs a router-decision row to memory/router.jsonl for
;; every gate (spend / approval / outcome). She stays in control: she decides
;; to watch; the Captain approves the spend; her own key makes the call.
;; ----------------------------------------------------------------------
(= (watch-film $path)
   (py-call (watchfilm.watch $path)))

;; ----------------------------------------------------------------------
;; Filmcraft — titles, subtitles, end credits. Local ffmpeg (static binary
;; + bundled fonts mounted at /opt/filmcraft). No cloud, no cost. 隙 writes
;; the title/credit text herself; the glue lays it onto video.
;; ----------------------------------------------------------------------
(= (title-card $spec)
   (py-call (filmcraft.title_card $spec)))

(= (subtitle $spec)
   (py-call (filmcraft.subtitle $spec)))

(= (credits $spec)
   (py-call (filmcraft.credits $spec)))

!(import_prolog_functions_from_file (library OmegaClaw-Core ./src/skills.pl) (shell first_char gc read_file_tail))

(= (metta $str)
   (let $code (sread $str)
        (repr (swrite (eval $code)))))

(= (pin $x)
   PIN-SUCCESS)

;; ----------------------------------------------------------------------
;; Subagent dispatch — see docs/reference-skills-subagent.md
;; and docs/tutorial-09-subagents.md for the full design.
;;
;; The dispatch primitive runs a bounded child LLM loop against a
;; configurable provider/model/endpoint (per the persona's JSON
;; config) and returns a single-string digest. Self-contained Python
;; module — no new dependencies beyond what lib_llm_ext already pulls in.
;; ----------------------------------------------------------------------

(= (delegate $goal $tools $persona $max_turns)
   (py-call (subagent.dispatch $goal $tools $persona $max_turns)))

(= (delegate $goal $tools $persona)
   (py-call (subagent.dispatch $goal $tools $persona 8)))

;; 1-arg form for OmegaClaw's single-arg-per-skill convention.
;; Hardcodes "researcher" as the default persona; deployments provide
;; their own persona config at memory/personas-subagent/researcher.json.
(= (delegate $goal)
   (py-call (subagent.dispatch $goal "" "researcher" 8)))
