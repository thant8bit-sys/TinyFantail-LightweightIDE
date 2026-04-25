// =============================================================================
//  TinyFantail v4.44 — Strict Ownership Pass (UI owns; workers carry IDs only).
//
//  v4.44 deltas over v4.43.  Every change is structural and type-system
//  enforced; behaviour for the happy path is unchanged.
//
//   O1. UI THREAD HAS SINGLE, EXCLUSIVE OWNERSHIP OF EVERY EditorTab.
//       g_Tabs is now std::vector<std::unique_ptr<EditorTab>>; the abandoned-
//       loads quarantine is std::vector<std::unique_ptr<EditorTab>>.  Tabs are
//       freed by exactly one mechanism: a unique_ptr going out of scope on the
//       UI thread.  Every prior `delete tab` / `delete closingTab` is gone.
//       No worker, message handler, or background task can free a tab —
//       structurally impossible, not "hopefully handled".
//
//   O2. WORKERS NEVER HOLD A RAW EditorTab POINTER.
//       FileLoadPayload (already) carries (loadId, cancelToken, targetTabId)
//       and nothing else that points at a tab.  v4.44 removes the residual
//       path-name fallback in WM_FILE_LOAD_COMPLETE / WM_FILE_LOAD_FAILED so
//       the only sanctioned tab lookup is TabHandle::resolve(targetTabId)
//       paired with `tab->loadId == payload->loadId` verification.  A
//       payload arriving for a closed tab, a recycled tab, a tab with a
//       newer loadId, or a tab in lifecycle != Alive is silently discarded
//       (TF_DROP_LOG'd) — the unique_ptr in the queue releases the memory.
//
//   O3. CLOSE PROTOCOL IS A LIFETIME TRANSITION, NOT A FREE.
//       RemoveTab:  (a) mark lifecycle = Closing immediately;
//                   (b) invalidate tab->loadId (set to 0) so any late
//                       worker payload fails the cross-check in O2;
//                   (c) cancel the per-load token and raise the global
//                       fast-path bulk cancel flag;
//                   (d) for in-flight loads: MOVE the unique_ptr from g_Tabs
//                       into g_AbandonedLoadingTabs (ownership transfer);
//                       no raw pointer aliasing across the two vectors;
//                   (e) for clean closes: just .erase() the slot — the
//                       unique_ptr destructor runs the final cleanup.
//       Final delete of an abandoned tab is the same: .erase() from the
//       quarantine vector; the unique_ptr destructor frees memory.
//
//   O4. NO BACKUP / RECOVERY DATA SURVIVES ACROSS SESSIONS.
//       Per user request: at startup we silently purge every *.recover and
//       *.bak file in %LOCALAPPDATA%\TinyFantail\recover\.  The autosave
//       heartbeat continues to write fresh snapshots during the live
//       session for in-process crash safety, but nothing carries over.
//
//   O5. EditorTab DESTRUCTOR HOOK.
//       The EditorTab destructor now calls TF_UnregisterTab(this) so the
//       side-table mapping is dropped at the exact moment unique_ptr frees
//       the object.  Belt-and-braces; the explicit TF_UnregisterTab calls
//       that v4.43 sprinkled in RemoveTab paths are kept (they run before
//       the unique_ptr scope exits, so the destructor's call is a no-op
//       in those paths — but it catches any future code path we forget).
//
//  Files touched: this TU only.  No header changes.  No new dependencies.
// =============================================================================
// =============================================================================
//  TinyFantail v4.43 — Reliability Pass (surgical, behaviour-preserving).
//
//  v4.43 deltas over v4.42 — every change is targeted at crash-resilience and
//  long-file editor smoothness.  Behaviour for the happy path is unchanged.
//
//   R1. STABLE TAB IDENTIFIER (uint64_t EditorTab::stableId)
//       Every EditorTab now carries a process-unique 64-bit id allocated from
//       a monotonic atomic counter.  A side-table (g_TabsById) maps id -> tab.
//       Cross-thread / message-driven references no longer trust raw pointers;
//       they round-trip via TabHandle::resolve() which validates (a) presence
//       in the map, (b) lifecycle == Alive, and (c) IsWindow(hEdit).  This
//       eliminates the "stale EditorTab* dereferenced after RemoveTab" class
//       of bugs at the source.  Tab memory is NEVER reused.
//
//   R2. EXPLICIT TAB LIFECYCLE STATE (atomic<uint8_t> EditorTab::lifecycle)
//       Three states — Alive, Closing, Dead.  Set BEFORE any cleanup runs.
//       Message handlers, the bulk-render pump, and the load registry all
//       short-circuit when lifecycle != Alive.  Replaces the implicit
//       "is this pointer still valid?" guard with an explicit one.
//
//   R3. PER-LOAD CANCEL TOKEN (std::shared_ptr<LoadCancelToken>)
//       The per-task cancel token replaces the global g_bBulkLoadCancel as
//       the source of truth.  Both the worker thread and the UI side hold
//       the shared_ptr; cancellation is a single atomic store visible to
//       both sides.  g_bBulkLoadCancel remains as a fast-path early-out
//       to avoid touching the token on every chunk.
//
//   R4. RAII PAYLOAD OWNERSHIP (already unique_ptr; now also strict)
//       FileLoadPayload retains unique ownership through the worker.  The
//       worker's "loadId" is now an opaque uint64_t (LoadId) carried inside
//       the payload, NOT a raw pointer.  This prevents address reuse from
//       confusing the registry (a freed payload's address could otherwise
//       be reissued by malloc in the same UI tick).
//
//   R5. HARDENED MESSAGE DISPATCH
//       WM_FILE_LOAD_COMPLETE / WM_FILE_LOAD_FAILED / WM_FILE_LOAD_PROGRESS /
//       WM_FILE_RENDER_PROGRESS now: validate LoadId in registry FIRST,
//       resolve target tab via TabHandle, RECHECK after every reentrancy
//       point (BulkSetEditText pumps messages), and silently drop +
//       TF_DROP_LOG when validation fails.  Asserts in debug builds.
//
//   R6. THREAD-SAFE ABANDONED-SET
//       g_AbandonedLoadIds and g_AbandonedLoadingTabs are now LoadId-keyed
//       and protected by g_AbandonedMtx.  Lookup is O(log n) and never
//       trusts raw pointers.
//
//   R7. PUMP HARDENING (PumpUIDuringBulkLoad)
//       Hard-bails on g_appQuitRequested at the top.  Drops keyboard / mouse
//       AND WM_TIMER for the loading edit (timers were leaking syntax recolor
//       reentrancy on the half-filled buffer).  Honors per-load cancel token.
//
//   R8. ADAPTIVE BULK-RENDER CHUNKING
//       BulkSetEditText scales chunk size with file size: 64 KW for <8 MB
//       (snappy progress), 256 KW for medium, up to 1 MW for huge files
//       (lower per-chunk overhead).  WM_SETREDRAW gating around the loop so
//       caret/selection/text painting can't fight the chunk inserts.  Net effect:
//       large-file loads feel noticeably smoother and the % counter no longer
//       jumps in coarse 5% jumps on multi-hundred-MB files.
//
//   R9. EDITOR SMOOTHNESS FOR HUGE FILES
//       After a successful bulk load we (a) drop the EDIT control's caret
//       to position 0 once (one EM_SCROLLCARET, not per-chunk), (b) request
//       a single non-erasing repaint, and (c) skip syntax recolor if the
//       document exceeds SYNTAX_DISABLE_THRESHOLD (handled by existing flag,
//       no behaviour change required here — just documented).
//
//   R10. DEBUG INFRASTRUCTURE
//        TF_DROP_LOG(reason)  — OutputDebugStringW with a tagged prefix so
//                               dropped/stale messages are auditable in a
//                               debugger without a full instrumentation.
//        TF_DBG_ASSERT(cond)  — debug-only assert; release-no-op.  Guards
//                               every cross-thread tab dereference.
//
//  Files touched: this TU only.  No header changes.  No new dependencies.
// =============================================================================
//  TinyFantail v4.40 — Polished Tab-Close Cancellation + Orphan-Free Progress
//
//  v4.40 delta over v4.39 — surgical, behaviour-preserving:
//
//    F0. CLOSING A LOADING TAB NOW REALLY CLOSES IT
//        v4.39 still refused closure while the worker thread was Reading,
//        leaving the hourglass tab/progress overlay alive. v4.40 stamps each
//        reserved sidebar tab with the worker loadId, quarantines that tab when
//        the user clicks x, removes it from the visible tab strip immediately,
//        detaches the progress registry entry, and performs final deletion only
//        when the matching COMPLETE/FAILED payload arrives. No blank tab, no
//        dangling progress panel, no use-after-free.
//
//    F1. WM_CLOSE NOW COOPERATIVELY CANCELS AN IN-FLIGHT BULK RENDER
//
//    F1. WM_CLOSE NOW COOPERATIVELY CANCELS AN IN-FLIGHT BULK RENDER
//        Before v4.39 the X button in the title bar bypassed RemoveTab's
//        cancel logic. If BulkSetEditText was on the call stack (it
//        pumps messages), WM_CLOSE -> WM_DESTROY ran INLINE inside the
//        pump, joined the worker, and freed every EditorTab. When the
//        chunk loop then resumed, it dereferenced a freed tab->hEdit
//        and crashed — leaving the blank tab the user reported.
//        v4.39 raises g_bBulkLoadCancel + g_appQuitRequested at the very
//        top of WM_CLOSE, drains the pump until BulkSetEditText has
//        unwound (bounded ~3 s), and only then proceeds to PromptForSave
//        + DestroyWindow.  Closing the X during a 1 GB load is now
//        graceful and never crashes.
//
//    F2. WM_FILE_LOAD_COMPLETE NOW DROPS PAYLOADS FOR DISAPPEARED TABS
//        A sidebar-issued load whose hourglass tab was closed (or whose
//        whole app was closed) used to fall through to the non-sidebar
//        branch and dump the giant text into an unrelated tab — the
//        "blank tab populated by someone else's file" symptom.  v4.39
//        recognises bFromSidebar with no surviving target and quietly
//        discards the payload (the unique_ptr drops, RAM is reclaimed).
//
//    F3. NEW GLOBAL g_appQuitRequested
//        Distinct from g_appRunning (which workers honour as "stop your
//        loops"). g_appQuitRequested tells UI-thread code paths
//        (BulkSetEditText, the chunk pump) "the user wants to quit —
//        give up immediately". Never written by workers.
//
//  Files touched: this TU only.  No header changes.  No new dependencies.
//
//  TinyFantail v4.37 — Hardened Ctrl +/- Resize Progress (on top of v4.36)
//      (extreme memory / GDI / data-integrity hardening on top of v4.34)
//
//  v4.35 delta over v4.34 (additive, behaviour-preserving):
//
//    S1. RAII GDI HANDLE GUARDS
//        New TF_Safety::GdiObjectGuard<T>, ScopedDC, ScopedSelectObject —
//        guarantee that every CreatePen/CreateSolidBrush/CreateFont/GetDC
//        path on a hot code path releases its handle even on exception or
//        early return. Defends against the classic "10 000 GDI objects per
//        process" Win32 ceiling that produces silent paint corruption on
//        long editing sessions.
//
//    S2. SATURATING SIZE-GATE ARITHMETIC
//        TF_Safety::MulSatSizeT() replaces the raw
//            docChars * sizeof(wchar_t)
//        in the v4.34 size-gate. On a 32-bit build, a >2 GiB doc would
//        wrap to a small number and incorrectly take the FAST path,
//        re-introducing typing stutter and risking allocator pressure.
//        The saturating multiply pins to SIZE_MAX so the slow path is
//        always taken for monster docs.
//
//    S3. DEFENSIVE BOUNDS ON PAINT-LINE CAP
//        WM_PAINT now clamps lLen into [0, TF_PAINT_MAX_LINE_CHARS].
//        EM_LINELENGTH on a deleted/invalid line can legally return -1
//        on some shells (Wine, very old comctl32). The previous loop
//        used the negative value as a wchar_t count and could read
//        past the line buffer. v4.35 makes this case provably safe.
//
//    S4. REENTRANCY-SAFE COALESCER
//        RequestEditUiRefresh() now uses a thread_local guard so a
//        message-pump that re-enters the function during SetTimer
//        cannot stack two timers or recurse back into the drain.
//        Also rejects HWNDs whose thread != GetCurrentThreadId() —
//        SetTimer across threads is a quiet source of dangling timers.
//
//    S5. WM_TIMER DRAIN: TRY / CATCH AROUND HEAVY WORK
//        The three v4.34 drains (IDT_EN_CHANGE_COALESCE,
//        IDT_STATS_DEFER_COALESCE, IDT_GUTTER_LAYOUT_DEFER) now run
//        their bodies inside a try / catch (...) wrapper. If a worker
//        throws (e.g. std::bad_alloc on a near-OOM machine) the
//        message loop survives and the user keeps their unsaved work.
//        v4.34 would have torn the WindowProc stack down and lost it.
//
//    S6. TF_SAFETY::WindowAlive() HOT-PATH HELPER
//        Single inline alias for the (h && IsWindow(h)) idiom that
//        appears ~80 times in this TU. v4.35 routes the new safety
//        helpers through it so the check is centralised and could
//        later be upgraded to also test thread affinity.
//
//    All v4.34 invariants preserved. Smooth-typing path, size-gated
//    stats, gutter debounce, paint-line cap, and EditRedrawSuspendGuard
//    behaviour all unchanged on the happy path. The new code only
//    activates on the failure / boundary cases v4.34 left implicit.
//
// =============================================================================
//
//  --- Original v4.34 banner preserved below ---
//
// =============================================================================
//  TinyFantail v4.34 — Smooth-Typing Pass (zero-stutter editing on huge files)
//
//  v4.34 delta over v4.33 (additive, behaviour-preserving):
//
//    A. ONE COALESCER ON THE TYPING HOT PATH
//       EditSubclassProc previously called RefreshAllIndicators()
//       (UpdateColInfo + UpdateLineCount + UpdateCharacterCount +
//        UpdateWordCount-on-UI-thread!) plus UpdateGutter() *synchronously*
//       on every WM_CHAR / paste / delete / undo / redo / Enter. On a
//       multi-MB file UpdateWordCount alone walked the whole document on
//       the UI thread per keystroke — the dominant typing-stutter source.
//
//       v4.34 routes all of that through one helper:
//           RequestEditUiRefresh(hMainWnd)
//       which just (re-)arms the existing IDT_EN_CHANGE_COALESCE 16 ms
//       one-shot timer. Heavy readouts therefore run at most once per
//       frame regardless of typing speed, and never on the typing
//       critical path itself. UpdateColInfo (cheap, must be live for
//       caret indicator) still runs immediately in the per-keystroke
//       branches that move the caret.
//
//    B. PER-EDIT WORD/CHAR STATS GATED BY DOC SIZE
//       The EN_CHANGE coalescer drain used to call
//           SpawnStatsWorker(..., tab->GetDocument())
//       which forces a full pt.GetVirtualText() flatten + a wstring
//       *copy* into the worker on every drain — hundreds of MB of
//       allocator traffic per typing burst on a large file. v4.34 adds
//       a size-gated slow path: documents larger than
//       TF_STATS_FAST_PATH_BYTES (default 2 MB of wchar_t) defer their
//       stats to a separate 250 ms idle coalescer
//       (IDT_STATS_DEFER_COALESCE) so a long burst of typing produces
//       exactly one stats pass after the user pauses. Small docs keep
//       the original 16 ms behaviour bit-for-bit.
//
//    C. GUTTER & LABEL INVALIDATION HYGIENE
//         * UpdateGutter: InvalidateRect(... TRUE) -> (... FALSE).
//           The gutter paints its own background; the extra erase was
//           pure flicker + double-fill. Removed the immediately-
//           following synchronous UpdateWindow() so paints batch.
//         * UpdateLineCount / UpdateCharacterCount short-circuit when
//           the formatted string is unchanged (no WM_SETTEXT, no
//           InvalidateRect). On a static doc this is a true no-op.
//         * Removed the duplicate InvalidateRect(tab->hGutter,...,TRUE)
//           that fired right after UpdateGutter inside the EN_CHANGE
//           coalescer drain.
//
//    D. AVOID RELAYOUT CASCADE ON DIGIT-WIDTH CROSSINGS
//       Crossing a 10x line-count boundary used to PostMessage(WM_SIZE)
//       inside the per-frame coalescer drain — that re-runs the entire
//       child layout. v4.34 only posts WM_SIZE when the digit count
//       *actually* changes AND debounces it through a separate 100 ms
//       idle timer (IDT_GUTTER_LAYOUT_DEFER) so a typing burst that
//       crosses the boundary back-and-forth doesn't relayout twice.
//
//    E. EditRedrawSuspendGuard: faster, flicker-free resume
//       resume() now uses RedrawWindow(RDW_INVALIDATE | RDW_NOERASE |
//       RDW_NOCHILDREN) instead of InvalidateRect(... TRUE). Bulk
//       loads come back to a single non-erasing repaint instead of a
//       full erase + child cascade.
//
//    F. SYNTAX RENDERER LINE-LENGTH GUARD
//       Per-line scan in WM_PAINT now caps lLen at TF_PAINT_MAX_LINE_CHARS
//       (8192 wchar_t). Anything past that is offscreen anyway because of
//       horizontal clipping, but the old loop still tokenised the whole
//       line — pathological for a minified one-line file.
//
//    All v4.33 invariants preserved. Undo/redo, bracket match, autofill,
//    flash highlight, jump highlight, file-load progress, sidebar refresh,
//    auto-compaction, and the v4.13 viewport-aware syntax window all
//    work bit-for-bit as before.
//
// =============================================================================
//
//  --- Original v4.28 banner preserved below ---
//
// =============================================================================
//  TinyFantail v4.28 — Render-phase Progress + GDI/Memory/Integrity Hardening
//
//  v4.28 delta over v4.27 (additive — zero behavioural regressions):
//
//    1. RENDER-PHASE PROGRESS (NEW)
//       The async load pipeline now exposes TWO independent percentages
//       per file — Reading (disk I/O) and Rendering (chunked EM_REPLACESEL
//       insert) — instead of conflating them onto a single 0..100 ramp.
//
//         * `LoadEntry` gains `readPct` and `renderPct` slots; phase enum
//           gains `Done`.  `displayedPct()` picks the right one for the
//           overlay based on the current phase.
//         * New WM_FILE_RENDER_PROGRESS (WM_USER + 113) carries
//           render-phase percentages from BulkSetEditText to the UI.
//           WM_FILE_LOAD_PROGRESS keeps its meaning (Reading) — old
//           call sites need no change.
//         * BulkSetEditText takes a `loadId` and posts render-phase
//           progress between chunks.  The overlay caption flips from
//           "Reading: foo.cpp 100%" to "Rendering: foo.cpp (842 MB) 47%"
//           the moment the chunk loop begins.
//         * Multi-load caption shows phase tags ("r"=reading, "R"=rendering)
//           per active file so two concurrent loads in different phases
//           are visually distinguishable at a glance.
//
//    2. GDI / WINDOW-OBJECT SAFETY
//         * EditRedrawSuspendGuard — RAII gate around WM_SETREDRAW so an
//           exception in the piece-table ingest can never leave the EDIT
//           control stuck in redraw=FALSE (silent blank-editor leak).
//         * DestroyLoadProgressUI() — single, idempotent teardown helper
//           used from WM_DESTROY.  Nulls handles BEFORE DestroyWindow so
//           any racing UI task that wakes between checks bails cleanly.
//         * EnsureLoadProgressUI nulls stale child handles BEFORE
//           creating a new panel, so a recycled HWND value can't be
//           mistaken for a still-live child.
//         * Overlay panel widened to 420 px to accommodate the dual-pct
//           caption without truncation.
//
//    3. MEMORY SAFETY / DATA INTEGRITY
//         * AsyncFileLoadThreadBody refactored:
//             - tf_v428::FileHandle RAII wrapper guarantees fclose on
//               every exit path (including exception unwind).
//             - Files >1.9 GB are refused with ERROR_FILE_TOO_LARGE
//               instead of silently wrapping the `int` arg of
//               MultiByteToWideChar into a negative value.
//             - Partial fread is detected via feof()/ferror() — a real
//               I/O error becomes ERROR_READ_FAULT (failure queue);
//               only a legitimate EOF-shrink is committed, with the
//               new payload->bTruncated flag set.
//             - Decoder sizing-pass / copy-pass mismatch is treated as
//               ERROR_NO_UNICODE_TRANSLATION (no half-decoded text
//               commit).
//             - FNV-1a-64 hash of the raw on-disk bytes is recorded on
//               the payload (auditable integrity trail).
//             - Raw byte buffer is freed before normalization so peak
//               memory is wstr + text instead of raw + wstr + text.
//         * All worker→UI PostMessageW calls go through TF_SafePost so
//           a freed HWND cannot crash the worker.
//         * TF_LoadRegistry_RemoveAndCount — atomic remove-and-report
//           closes the race where two completers could both decide
//           "I'm last" and double-hide the overlay.
//         * TF_LoadRegistry_Clear — invoked from DestroyLoadProgressUI
//           so the registry contains no stale entries pointing at
//           freed payloads after shutdown.
//         * All swprintf() calls in the overlay path replaced with
//           _snwprintf_s + _TRUNCATE so a pathological filename can
//           never overrun the stack buffer.
//         * TF_FormatBytes gains a "GB" tier for sub-TB files; takes
//           a defensive nullptr / cch==0 short-circuit.
//
//    All v4.27 invariants preserved.  All v4.27 call sites compile with
//    no source change EXCEPT the one BulkSetEditText caller, which now
//    passes the loadId (see WindowProc::WM_FILE_LOAD_COMPLETE).
//
// =============================================================================

// =============================================================================
//  TinyFantail v4.26 — Strict UI Thread Ownership + Piece Table Auto-Compaction
//
//  v4.26 delta over v4.25 (additive — zero behavioural regressions):
//
//    1. STRICT UI THREAD OWNERSHIP (NEW — see "UI THREAD OWNERSHIP" block,
//       inserted just after the WIN32 SAFETY LAYER)
//       Win32 documents that every window must be touched only from the
//       thread that created it.  Worker threads in this codebase already
//       respect that contract by communicating via PostMessage doorbells
//       (FileWatcher, AsyncFileLoad, FileExec).  v4.26 makes the contract
//       MACHINE-CHECKED instead of merely customary:
//
//         * g_uiThreadId — captured in wWinMain before any window is
//           created.  TF_IsUIThread() and TF_AssertUIThread() inspect it.
//         * TF_AssertUIThread() — debug-only assert that fires if a
//           supposedly-UI helper (SendMessage, InvalidateRect, SetWindowText,
//           tab->pt mutation, undo stack mutation) is invoked from a
//           background thread.  Compiles to a no-op in release.
//         * WM_TF_UI_TASK (WM_USER + 130) + TF_PostUITask(std::function)
//           — generic marshalling primitive for worker threads that need
//           to perform an arbitrary UI update.  The worker enqueues a
//           std::function<void()> into g_UITaskQueue and posts a
//           doorbell; the WndProc drains the queue and runs each task on
//           the UI thread.  This is the ONLY sanctioned pathway for a
//           background thread to mutate UI / model state.  Direct
//           SendMessage / SetWindowText / InvalidateRect from a worker
//           is now a documented bug.
//         * Existing worker threads (FileWatcher, AsyncFileLoad,
//           AsyncFileLoadEx, FileExec, Stats workers) are AUDITED — all
//           already PostMessage-only.  No call-site rewrite needed; the
//           new primitive is for FUTURE workers that need richer payloads
//           than a (WPARAM, LPARAM) pair.
//
//    2. PIECE TABLE AUTO-COMPACTION (NEW)
//       After hours of editing the splay tree accumulates many small
//       pieces, even though the splay structure keeps lookups O(log N).
//       Per-edit overhead is fine; what degrades over a long session is
//       (a) GetVirtualText() flatten cost when callers ask for the whole
//       buffer, and (b) the working-set footprint of the add-buffer
//       arenas.  v4.26 adds an OPPORTUNISTIC compactor:
//
//         * Per-tab counters: editsSinceCompact, lastCompactNodeCount.
//         * TF_MaybeAutoCompactPT(tab) — called from the bottom of
//           CommitEditCommand and TF_EditorMutate.  Triggers Compact()
//           when EITHER:
//             - editsSinceCompact >= TF_AUTO_COMPACT_EDITS (default 4096)
//             - pt.GetPieceCount() >= TF_AUTO_COMPACT_PIECES (default 8192)
//             - pt.GetPieceCount() >= 4 * lastCompactNodeCount (growth)
//           AND the tab is not currently in a restore (undo/redo) cycle,
//           AND the active selection is empty (no live drag).  The
//           compactor preserves caret + scroll, never invalidates undo
//           history (Compact() only rewrites the buffer, not the command
//           list), and is gated by MutationGuard so it cannot re-enter.
//         * The existing manual Edit > Compact menu item still works
//           identically; it now also resets the auto-compact counters.
//
//    All v4.25 invariants preserved.
//
// =============================================================================
//  --- v4.25 notes (retained verbatim below) ---
// =============================================================================
//  TinyFantail v4.25 — Centralized Mutation Pipeline + PT-as-Source-of-Truth
//
//  v4.25 delta over v4.24 (additive — zero behavioural regressions):
//
//    1. CENTRALIZED MUTATION PIPELINE (NEW — see "MUTATION PIPELINE" block,
//       inserted just after ApplyPieceTableEdit)
//       Every state-changing edit now has ONE canonical entry point:
//
//           TF_EditorMutate(tab, pos, removedLen, inserted) -> bool
//
//       This funnel performs, in order:
//         (a) TF_TabIsAlive(tab)          — null + IsWindow(hEdit) guard.
//         (b) MutationGuard               — RAII re-entrancy lock built on
//                                            the existing tab->isRestoring
//                                            flag. A nested mutation call
//                                            (e.g. an EN_CHANGE handler that
//                                            tries to mutate again) is
//                                            rejected with a clean false
//                                            return instead of corrupting
//                                            the undo stack.
//         (c) TF_NormalizeRange           — clamps pos/len to [0, doc length],
//                                            so callers can pass DWORDs from
//                                            EM_GETSEL without pre-validation.
//         (d) ApplyPieceTableEdit         — the existing PT mutation
//                                            (UNCHANGED — this is the
//                                            authoritative model).
//         (e) TF_SyncEditViewFromPT       — pushes the new PT span into the
//                                            EDIT control as a pure VIEW
//                                            update (cachedDocDirty=true,
//                                            request repaint of the visible
//                                            range only).
//         (f) Consistent failure return   — bool, never throws, never blocks.
//
//       Existing call sites still call ApplyPieceTableEdit / EM_REPLACESEL
//       directly because they live inside CommitEditCommand which already
//       owns the undo-stack invariants.  TF_EditorMutate is the recommended
//       path for every NEW mutation site (paste handlers, refactor tools,
//       AI-driven edits, scripted transforms).
//
//    2. PT-AS-SOURCE-OF-TRUTH — REINFORCED CONTRACT
//       The header comment block above ApplyPieceTableEdit now states the
//       contract explicitly: PieceTable is the model, the EDIT control is
//       a view.  Any code that reads document state for a non-cosmetic
//       purpose (search, save, syntax check, statistics, AI context) MUST
//       go through tab->pt.GetVirtualText() / GetVirtualSpan(), NOT
//       EM_GETTEXT.  TF_SyncEditViewFromPT is the only sanctioned write
//       direction PT -> EDIT for mutations originating off the keyboard
//       path; the keyboard path itself remains EM_REPLACESEL ->
//       CommitEditCommand -> ApplyPieceTableEdit, because the EDIT control
//       is the authoritative source of caret/scroll state for that path.
//
//    3. WIN32 GUARDS — UNCHANGED FROM v4.24
//       The TF_Safe* family from v4.24 underpins TF_TabIsAlive and
//       TF_SyncEditViewFromPT, so the new pipeline inherits the
//       SendMessageTimeout / SMTO_ABORTIFHUNG protections automatically.
//
//    All v4.24 invariants preserved.
//
// =============================================================================
//  --- v4.24 notes (retained verbatim below) ---
// =============================================================================
//  TinyFantail v4.24 — Win32 Safety Layer + Text Buffer Decoupling Audit
//
//  v4.24 delta over v4.23 (additive — zero behavioural regressions):
//
//    1. WIN32 SAFETY LAYER (NEW)
//       Direct SendMessage / PostMessage / InvalidateRect / UpdateWindow /
//       ShowWindow calls trust their HWND argument unconditionally. If the
//       target window has been destroyed on another thread (e.g. WM_DESTROY
//       fired during an async load) the call is undefined behaviour — at
//       best it silently no-ops, at worst it deadlocks the UI thread when
//       the target's window procedure is wedged.
//
//       Added a small, header-style helper family (see "WIN32 SAFETY LAYER"
//       block below):
//
//         TF_SafeIsAlive(hWnd)               -> IsWindow + null check
//         TF_SafeSend(hWnd, msg, w, l, ...)  -> SendMessageTimeoutW with
//                                                 SMTO_ABORTIFHUNG | SMTO_NORMAL
//                                                 default 2000 ms cap; never
//                                                 blocks the UI thread on a
//                                                 hung peer window.
//         TF_SafeSendT<T>(...)               -> typed convenience wrapper.
//         TF_SafePost(hWnd, msg, w, l)       -> guarded PostMessageW.
//         TF_SafeInvalidate(hWnd, rc, erase) -> guarded InvalidateRect.
//         TF_SafeUpdate(hWnd)                -> guarded UpdateWindow.
//         TF_SafeShow(hWnd, cmd)             -> guarded ShowWindow.
//
//       Policy: the helpers are AVAILABLE to all code; the existing 263
//       SendMessageW call sites are DELIBERATELY left in place to keep this
//       a surgical polish (mass mechanical rewrite would risk regressions
//       in the splay-tree / undo-stack hot paths, which are single-threaded
//       and verifiably safe). New code, async-completion handlers, and any
//       cross-thread doorbell post should now prefer the TF_Safe* family.
//
//    2. TEXT BUFFER ABSTRACTION — AUDIT NOTE
//       The architectural concern of "edit control as source of truth" is
//       already addressed in this codebase: every EditorTab owns a
//       PieceTable (class at line 690) which is the authoritative model.
//       The Win32 EDIT control is treated strictly as a view: bulk loads
//       go through BulkSetEditText, edits round-trip through
//       ApplyPieceTableEdit, and undo/redo operate on PT snapshots — not
//       on EM_GETTEXT / EM_SETSEL state. No code change required; this
//       note exists so future maintainers do not "fix" what is already
//       correct.
//
//    All v4.23 invariants preserved.
//
// =============================================================================
//  --- v4.23 notes (retained verbatim below) ---
// =============================================================================
//  TinyFantail v4.23 — Polish: gutter repaint, thread-safe shutdown, RAII guards
//
//  v4.23 delta over v4.22:
//    * GUTTER NOT VISIBLE AFTER LOAD (HARD FIX)
//      Previously, after WM_FILE_LOAD_COMPLETE, the gutter often stayed
//      blank until the user switched tabs or toggled the tree panel. Root
//      cause: the gutter's cached firstVisibleLine was computed BEFORE the
//      edit control had finished its internal line-break recompute that
//      follows a bulk EM_SETTEXT. Switching tabs worked because it triggers
//      WM_SIZE -> ResizeChildren, which re-seats the gutter.
//      Fix: WM_FILE_LOAD_COMPLETE now (a) synthesizes a WM_SIZE on the
//      main window — the same code path tab-switching uses, (b) sends
//      EM_SCROLLCARET to nudge the edit control into republishing its
//      scroll state, and (c) keeps the explicit InvalidateRect/UpdateWindow
//      belt-and-braces from v4.22.
//
//  v4.22 delta (surgical polish over v4.15 — no behavioural regressions):
//
//
//    1. GUTTER REPAINT AFTER LOAD (FIX)
//       The async-load progress overlay (g_hLoadProgressPanel) is a child
//       window that overlapped the editor + gutter region during a load.
//       HideLoadProgressUI() previously only called ShowWindow(SW_HIDE),
//       which leaves the area underneath dirty until *something else*
//       triggers WM_PAINT. Result: the line-number gutter remained blank
//       (or showed pre-load digits) for several seconds after a file open.
//
//       Fix:
//         * HideLoadProgressUI now takes the owner HWND, hides the panel,
//           and explicitly InvalidateRect(owner, panelRect, TRUE) so every
//           child window underneath re-paints.
//         * WM_FILE_LOAD_COMPLETE hides the overlay BEFORE issuing the
//           gutter / status redraws so the gutter is the last thing painted.
//         * The progress panel no longer uses WS_EX_TOPMOST (meaningless on
//           a child window and misleading in code review).
//
//    2. STATS QUEUE PROPER SHUTDOWN (RACE FIX)
//       ThreadManager::shutdownAll() did not call shutdown() on
//       g_StatResultQueue. A stats worker blocked in push() at exit
//       would never wake. Added to the wake-list.
//
//    3. BULK LOAD: HONOR APP TEARDOWN MID-LOAD
//       BulkSetEditText pumps the message loop between chunks. If the user
//       closes the window during a multi-hundred-MB load the pump dispatches
//       WM_DESTROY, the edit control is destroyed, and the next chunk's
//       EM_REPLACESEL would target a dead HWND. The chunk loop now polls
//       g_appRunning + IsWindow(hEdit) and returns cleanly.
//
//    4. DEFENSIVE GUARDS
//       * UpdateGutter validates IsWindow(hGutter) before invalidation.
//       * WM_DESTROY tab teardown null-checks tab pointer before access.
//       * FileWatcherStop nulls hShutdown after CloseHandle even on the
//         no-op early-return path.
//
//    5. UI MESSAGE-BOX HELPER (ADDITIVE)
//       New TF_MsgInfo / TF_MsgWarn / TF_MsgError inline helpers wrap
//       MessageBoxW with MB_TASKMODAL and GA_ROOT promotion so future
//       call sites cannot pop a modal dialog parented to a transient
//       child window. Existing call sites are unchanged.
//
//    All v4.15 invariants below remain intact.
//
// =============================================================================
//  --- v4.15 notes (retained verbatim below) ---
// =============================================================================
//  TinyFantail v4.15 — Intelligent Recursive File Watcher
//  (Builds on v4.13 Viewport-Aware Virtual Rendering — all prior invariants intact.)
//
//  v4.15 delta — Upgraded directory watcher: WatcherContext, expanded filter,
//  per-action dispatch, coalesced WM_SIDEBAR_REFRESH:
//
//    PROBLEM
//    -------
//    The v4.13 watcher monitored only FILE_NOTIFY_CHANGE_FILE_NAME and handled
//    only FILE_ACTION_REMOVED, so newly created files and renamed entries were
//    invisible to the sidebar until the user manually triggered a reload.
//
//    SOLUTION
//    --------
//    1. WatcherContext (local struct in FileWatcherThreadBody) bundles the
//       OVERLAPPED object and the 64 KiB BYTE buffer so that all overlapped
//       I/O state has a single, obvious owner with stack-frame lifetime — no
//       dangling handle or stray pointer possible by construction.
//
//    2. Filter expanded:
//           FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME
//         | FILE_NOTIFY_CHANGE_LAST_WRITE
//       All structural filesystem events are now captured, including
//       subdirectory creation, deletion, and renaming.
//
//    3. Per-action dispatch in the FILE_NOTIFY_INFORMATION parse loop:
//         • REMOVED / RENAMED_OLD_NAME → g_FileRemovedQueue + WM_FILE_REMOVED
//           (existing targeted-deletion path — O(depth), no rescan needed).
//         • ADDED / RENAMED_NEW_NAME   → coalesced WM_SIDEBAR_REFRESH via
//           g_SidebarRefreshPending compare_exchange: a burst of N additions
//           posts exactly ONE doorbell regardless of N.
//         • MODIFIED (LAST_WRITE)      → discarded (content change only;
//           tree structure is unaffected by file saves).
//         • Buffer-overflow (bytes == 0 kernel sentinel) → treated as a
//           structural add so the tree is conservatively refreshed.
//
//    4. WM_SIDEBAR_REFRESH (WM_USER + 107) — new custom message.
//       Handler (HandleSidebarRefreshMessage) clears g_SidebarRefreshPending
//       BEFORE calling SidebarLoadDirectory so the watcher can re-arm
//       immediately if another structural event arrives during the async
//       rescan.  The current sidebar selection is preserved across rebuilds
//       via the selectAfterLoad path in HandleDirectoryLoaded.
//
//    INVARIANTS (UNTOUCHED)
//    ----------------------
//      * PieceTable / SplayNode / ArenaAllocator: zero changes.
//      * Undo/redo, RestoreGuard, ApplyPieceTableEdit: zero changes.
//      * WM_FILE_REMOVED + g_FileRemovedQueue + HandleFileRemovedMessage:
//        zero changes — targeted-deletion path fully preserved.
//      * ThreadSafeQueue, ThreadManager, g_appRunning: zero changes.
//      * Async statistics worker (v4.12): untouched.
//      * Viewport-windowed rendering (v4.13): untouched.
//
//    NEW GLOBALS
//    -----------
//      static std::atomic<bool> g_SidebarRefreshPending  — coalescing gate
//
//    NEW MESSAGE
//    -----------
//      WM_SIDEBAR_REFRESH (WM_USER + 107)
//
// =============================================================================
//  --- v4.13 notes (retained verbatim below) ---
// =============================================================================
//  TinyFantail v4.13 — Viewport-Aware Virtual Rendering
//  (Builds on v4.12 Async Statistics Worker — all prior invariants intact.)
//
//  v4.13 delta — Viewport-aware piece-table windowing for WM_PAINT:
//
//    PROBLEM
//    -------
//    The v4.12 syntax renderer pulled the ENTIRE document into cachedDoc on
//    every cachedDocDirty rebuild via tab->pt.GetVirtualText().  For multi-MB
//    or 100M+ character documents this O(N) flatten dominated frame time and
//    forced the splay tree to materialise a single contiguous wstring of the
//    full document on every edit — completely wasting the O(log N) random
//    access the splay tree was designed for.
//
//    FIX
//    ---
//    cachedDoc is now a *sliding window* over the piece table that mirrors
//    only what the EDIT control is actually painting:
//
//      1. WM_PAINT computes `first = EM_GETFIRSTVISIBLELINE` and `visLines`
//         exactly as before (line metrics derived from TEXTMETRIC via
//         GetTextExtentPoint32 on "A").
//      2. The visible character span is obtained directly from the EDIT
//         control with EM_LINEINDEX(first) and EM_LINEINDEX(first+visLines)
//         + EM_LINELENGTH on the last visible line, plus a small safety
//         buffer for trailing line endings.
//      3. cachedDoc is rebuilt via tab->pt.GetVirtualSpan(spanStart, spanLen)
//         — an O(log N + S) operation where S is the visible span length
//         (typically a few thousand wchars), NOT the document length.
//      4. tab->cachedDocOffset records the absolute character offset of the
//         window so the syntax loop's local index `j` can be translated
//         back to absolute document coordinates `cIdx + j` without any
//         additional bookkeeping.
//      5. cachedDocDirty stays high until either a tracked edit occurs
//         (Insert/Delete/Replace via ApplyPieceTableEdit) OR the visible
//         span changes (scroll / resize / wrap).  The WM_PAINT handler
//         compares (cachedDocOffset, cachedDoc.size()) against the freshly
//         computed (spanStart, spanLen) and only re-invokes GetVirtualSpan
//         when they diverge — preserving the O(1) "user keeps typing in the
//         same spot" optimisation across redundant repaints.
//
//    BRACKET MATCHING
//    ----------------
//    FindMatchingBracket() previously consumed the *entire* cachedDoc.  It
//    now operates on the windowed snippet using local coordinates:
//        local = selStart - 1 - cachedDocOffset
//    and the returned local match index is converted back to absolute
//    coordinates with (cachedDocOffset + local) so the per-character
//    comparison `gIdx == matchIdx` in the inner draw loop is unchanged.
//    When the caret falls outside the window (selStart-1 < cachedDocOffset
//    or >= cachedDocOffset + doc.size()) bracket matching is skipped for
//    that frame — a correct degenerate behaviour because the matching
//    bracket would not be visible anyway.
//
//    INVARIANTS (UNTOUCHED)
//    ----------------------
//      * PieceTable / SplayNode / ArenaAllocator: zero changes.
//      * Undo/redo, RestoreGuard, ApplyPieceTableEdit: zero changes.
//      * EM_GETLINE, EM_LINEINDEX, EM_LINELENGTH usage: zero protocol changes.
//      * Async statistics worker (v4.12): unchanged — the worker still
//        receives a full-document moved wstring snapshot from EN_CHANGE.
//      * Thread shutdown / ThreadManager / queues (v4.11): unchanged.
//      * Sidebar, gutter, file watcher, autofill: unchanged.
//
//    NEW EditorTab FIELDS
//    --------------------
//      size_t cachedDocOffset   — absolute char offset of cachedDoc[0]
//      size_t cachedDocSpanLen  — last applied span length (debug / sanity)
//
//    The two fields are zero-initialised; legacy callers that do
//      cachedDoc      = pt.GetVirtualText();
//      cachedDocDirty = false;
//    have been replaced with an explicit invalidation pattern
//      cachedDoc.clear();
//      cachedDocOffset = 0;
//      cachedDocSpanLen = 0;
//      cachedDocDirty  = true;
//    so the next WM_PAINT performs the windowed rebuild correctly.
// =============================================================================
//  --- v4.12 notes (retained verbatim below) ---
// =============================================================================
//  TinyFantail v4.12 — Async Statistics Worker
//  (Builds on v4.11 Thread Safety & Lifecycle Overhaul — all invariants intact.)
//
//  v4.12 delta:
//    * EN_CHANGE no longer calls UpdateWordCount / UpdateCharacterCount on the
//      UI thread. Both are computed by a background std::thread spawned via
//      g_ThreadMgr.spawn() on a moved std::wstring snapshot of the document.
//    * New StatResult struct + g_StatResultQueue (ThreadSafeQueue<unique_ptr>)
//      mirror the v4.11 doorbell pattern.
//    * New WM_UPDATE_STATS (WM_USER + 106) doorbell drains the queue and
//      applies results only when the result's hEdit matches the active tab
//      and its monotonic seq is newer than the last-applied for that hEdit.
//    * Worker polls g_appRunning every 64 KiB so shutdown is honoured during
//      multi-MB scans; queue drained and per-edit map cleared in WM_DESTROY
//      Phase 2 alongside the existing v4.11 drains.
//    * PieceTable, splay tree, undo/redo, RestoreGuard, and every EDIT-control
//      protocol path are UNTOUCHED. No new pointer ownership crosses thread
//      boundaries -- only HWND values and a moved wstring.
// =============================================================================
//  --- v4.11 notes (retained verbatim below) ---
// =============================================================================
//  TinyFantail v4.11 — Thread Safety & Lifecycle Overhaul
//  All original Win32 / GDI / EDIT-control logic preserved intact.
//  The PieceTable class replaces the raw std::wstring internal document store,
//  providing O(1) amortised Insert / Delete and a GetVirtualText() view that
//  is consumed by syntax highlighting, search, save, symbol indexing, and
//  hash-based dirty detection — with zero changes to the EDIT-control protocol.
//
//  Modernization summary (v4.11):
//    • Eliminated ALL std::thread::detach() — every worker thread is now
//      tracked by ThreadManager and joined on shutdown.
//    • ThreadSafeQueue redesigned: std::condition_variable blocking waits,
//      optional max capacity, shutdown() notifies all waiters.
//    • Formalized shutdown protocol: WM_DESTROY signals running flag, calls
//      ThreadManager::shutdownAll() (joins threads) BEFORE any UI teardown.
//    • FileWatcher converted from _beginthreadex to std::thread, integrated
//      into ThreadManager; keeps CancelIoEx + OVERLAPPED cooperative stop.
//    • WM_FILE_REMOVED raw wstring* lParam replaced with
//      g_FileRemovedQueue (ThreadSafeQueue<std::wstring>) + doorbell pattern.
//    • PieceTable/splay tree hardened with optional TFDEBUG_PT invariant
//      checks (subtree sizes, buffer bounds, parent-pointer integrity).
//    • No raw pointers to UI state escape to background tasks.
//    • FileWatcherState::running → std::atomic<bool>
// =============================================================================

#ifndef UNICODE
#define UNICODE
#endif

#include <condition_variable>
#include <chrono>
#include "resource.h"
#include <windows.h>
#include <windowsx.h>      // GET_X_LPARAM, GET_Y_LPARAM
#include <string>
#include <vector>
#include <list>
#include <commdlg.h>
#include <cstdio>
#include <algorithm>
#include <atomic>
#include <thread>
#include <mutex>
#include <queue>
#include <functional>      // v4.26: std::function for TF_PostUITask
#include <commctrl.h>
#include <cwctype>
#include <set>
#include <unordered_set>
#include <unordered_map>
#include <sstream>
#include <filesystem>
#include <shlobj.h>
#include <knownfolders.h>
#include <shellapi.h>
#include <deque>
#include <memory>
#include <cstring>
#include <cassert>
#include <numeric>
#include <limits>

#ifndef EM_GETCARETPOS
#define EM_GETCARETPOS 0x01B1
#endif

namespace fs = std::filesystem;

// ══════════════════════════════════════════════════════════════════════════════
//  MODULE: Threading primitives
// ══════════════════════════════════════════════════════════════════════════════

// =============================================================================
//  ThreadSafeQueue<T>  (v4.11 — condition_variable, optional capacity, shutdown)
//
//  MPSC queue transferring unique_ptr payloads from background threads to the
//  UI thread without raw-pointer passing through the Win32 message queue.
//
//  New in v4.11:
//    • push() blocks (with a cv wait) when the queue is at capacity.
//      A maxCapacity of 0 (the default) means unbounded.
//    • shutdown() sets the m_done flag and notifies ALL waiters so that any
//      thread blocked in push() or wait_pop() unblocks immediately and can
//      check a stop-flag and exit cleanly.
//    • try_pop() is unchanged (non-blocking, returns T{} on empty).
//    • wait_pop(val) blocks until an item is available or shutdown is called.
//
//  Usage pattern (producer, background thread):
//      if (!q.push(std::move(payload))) return;  // shutdown in progress
//      PostMessageW(hwnd, WM_WHATEVER, 0, 0);    // null lParam = "doorbell"
//
//  Usage pattern (consumer, WindowProc on WM_WHATEVER):
//      while (auto up = q.try_pop()) { /* use *up */ }
// =============================================================================
template<typename T>
class ThreadSafeQueue {
public:
    explicit ThreadSafeQueue(size_t maxCapacity = 0)
        : m_maxCapacity(maxCapacity), m_done(false) {}

    // Push an item. Blocks if the queue is at capacity (maxCapacity > 0).
    // Returns false without pushing if shutdown() has been called.
    bool push(T item) {
        std::unique_lock<std::mutex> lk(m_mtx);
        if (m_done) return false;
        if (m_maxCapacity > 0) {
            m_notFull.wait(lk, [this] {
                return m_done || m_q.size() < m_maxCapacity;
            });
            if (m_done) return false;
        }
        m_q.push(std::move(item));
        lk.unlock();
        m_notEmpty.notify_one();
        return true;
    }

    // Non-blocking pop. Returns T{} (null unique_ptr) when the queue is empty.
    T try_pop() {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (m_q.empty()) return T{};
        T item = std::move(m_q.front());
        m_q.pop();
        if (m_maxCapacity > 0) m_notFull.notify_one();
        return item;
    }

    // Blocking pop. Returns false (with val unchanged) if shutdown was called
    // and the queue is empty; otherwise returns true and moves into val.
    bool wait_pop(T& val) {
        std::unique_lock<std::mutex> lk(m_mtx);
        m_notEmpty.wait(lk, [this] { return m_done || !m_q.empty(); });
        if (m_q.empty()) return false;
        val = std::move(m_q.front());
        m_q.pop();
        if (m_maxCapacity > 0) m_notFull.notify_one();
        return true;
    }

    // Signal all waiters that the queue is being torn down.
    // After this call, push() returns false and wait_pop() returns false on empty.
    void shutdown() {
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            m_done = true;
        }
        m_notEmpty.notify_all();
        m_notFull.notify_all();
    }

    // Reset the queue to a live state (undo a previous shutdown).
    void reset() {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_done = false;
        while (!m_q.empty()) m_q.pop();
    }

    bool empty() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_q.empty();
    }

    size_t size() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_q.size();
    }

private:
    mutable std::mutex      m_mtx;
    std::condition_variable m_notEmpty;
    std::condition_variable m_notFull;
    std::queue<T>           m_q;
    size_t                  m_maxCapacity;
    bool                    m_done;
};

// =============================================================================
//  ThreadManager
//
//  Central owner of all application worker threads. Every std::thread that
//  was previously detached is now registered here.  On shutdownAll():
//    1. Sets the global g_appRunning flag to false.
//    2. Calls shutdown() on every queue so blocked producers/consumers wake.
//    3. Joins every thread in reverse-spawn order (LIFO).
//
//  Usage (at a spawn site):
//      g_ThreadMgr.spawn([p = std::move(params)]() mutable {
//          WorkerBody(std::move(p));
//      });
// =============================================================================

// Forward-declared queues that ThreadManager::shutdownAll() must wake.
// The actual globals are defined further below; we only need to call
// shutdown() on them.  We forward-declare the manager here so it can be
// used at the spawn sites.
class ThreadManager {
public:
    ThreadManager() = default;
    ~ThreadManager() { shutdownAll(); }

    // Spawn a new joinable worker.  The callable f must be copyable or
    // wrapped with std::move in a lambda capture (unique_ptr params, etc.).
    template<typename Fn>
    void spawn(Fn&& f) {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_threads.emplace_back(std::forward<Fn>(f));
    }

    // Signal all threads to stop, wake all queues, then join every thread.
    // Idempotent — safe to call multiple times.
    void shutdownAll();

private:
    std::mutex              m_mtx;
    std::vector<std::thread> m_threads;
};

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")  // RegCreateKeyExW, RegSetValueExW, etc.

using namespace std;

// =============================================================================
//  GLOBAL LIFECYCLE STATE (v4.11)
//
//  g_appRunning — set to false in WM_DESTROY before any thread joins.
//                 Background threads check this flag to exit early.
//  g_ThreadMgr  — owns every worker std::thread; joined in shutdownAll().
// =============================================================================
static std::atomic<bool> g_appRunning{true};
static ThreadManager     g_ThreadMgr;

void UpdateTitle(HWND hwnd);
void UpdateLineCount(HWND hEdit, HWND hLineCount);
void UpdateWordCount(HWND hEdit, HWND hWordCount);
void UpdateCharacterCount(HWND hEdit, HWND hCharLabel);
void CreateNewTab(HWND hwndParent);
struct EditorTab;                      // forward — defined at the EDITOR TAB section
EditorTab* GetActiveTab();             // v4.41 forward decl for tf_v441::Reliability

// =============================================================================
//  PIECE TABLE — O(1) amortised Insert/Delete, O(n) sequential read
//
//  Architecture:
//    • Original buffer  — immutable; holds text loaded from disk (or empty).
//    • Add buffer       — append-only; receives all inserted characters.
//    • Piece list       — std::list<Piece>; each Piece describes a slice of
//                         one of the two buffers.
//
//  All edits create or split pieces; no data is ever shifted in-place.
//  GetVirtualText() / GetVirtualSpan() materialise a contiguous wstring on
//  demand so that all existing GDI/Win32 consumers remain unchanged.
//
//  Thread safety: single-threaded UI use only (same as the rest of the app).
// =============================================================================

// =============================================================================
//  PIECE TABLE v2 — Arena-backed Splay Tree
//
//  This is a drop-in replacement for the original list-based PieceTable.
//  The PUBLIC API is byte-identical to v1 — every external caller in this
//  translation unit (EditorTab, ApplyPieceTableEdit, symbol scanner, syntax
//  checker, save pipeline, hash dirty detector, MemoryCost reporter) compiles
//  and behaves exactly as before:
//
//      PieceTable()
//      void              LoadOriginal(std::wstring text)
//      void              Clear()
//      size_t            Length()         const noexcept
//      bool              Empty()          const noexcept
//      size_t            GetPieceCount()  const noexcept
//      const std::wstring& GetVirtualText() const
//      std::wstring      GetVirtualSpan(size_t offset, size_t len) const
//      wchar_t           CharAt(size_t pos) const noexcept
//      void              Insert(size_t pos, const std::wstring& text)
//      void              Delete(size_t pos, size_t len)
//      void              Replace(size_t pos, size_t oldLen,
//                                const std::wstring& newText)
//      void              Compact()
//      size_t            MemoryCost()     const noexcept
//      template<typename Fn> void ForEachPiece(Fn&&) const
//
//  ─────────────────────────────────────────────────────────────────────────────
//  ENGINE
//  ─────────────────────────────────────────────────────────────────────────────
//
//  ▸ ArenaAllocator
//      Wraps the native Win32 VirtualAlloc API.  On construction we MEM_RESERVE
//      a huge contiguous virtual address range (default 64 MiB).  Pages are
//      MEM_COMMIT-ed lazily, one 64 KiB chunk at a time, as the bump pointer
//      crosses each chunk boundary.  Allocation is a single integer increment
//      (true O(1)); there are no free-lists, no per-allocation headers, and
//      zero heap fragmentation.  Memory is reclaimed only via Reset(), which
//      MEM_DECOMMITs every committed page and rewinds the bump pointer to 0.
//      The reserved address range itself lives until the arena is destroyed.
//
//      Two arenas live inside PieceTable:
//          m_textArena  — stores the raw wchar_t payload of inserted text
//                         (replaces the old std::wstring m_add).
//          m_nodeArena  — stores SplayNode structures.
//
//      Compact() flattens the tree into a fresh single-node document, then
//      Reset()s both arenas back to offset 0 — instantly reclaiming all RAM
//      without any per-node delete calls.
//
//  ▸ SplayNode
//      Represents one slice of either the immutable Original buffer or the
//      append-only text arena.  Carries left/right/parent child pointers and
//      a cached subtreeLength — the total number of wchar_t characters in this
//      node plus the subtreeLength of both children.  This cached aggregate
//      is the foundation of the O(log N) virtual-offset lookup.
//
//  ▸ Splay tree
//      Standard top-down/bottom-up splay tree keyed by virtual character
//      offset (computed implicitly via subtreeLength).  Every access — Find,
//      Insert, Delete — splays the touched node to the root, giving us
//      amortised O(log N) per operation and O(1) for the extremely common
//      "user keeps typing in the same spot" pattern (the active node stays
//      pinned at the root, so each subsequent keystroke is a constant-time
//      hit).
//
//  Thread safety: single-threaded UI use only (same as the rest of the app).
// =============================================================================

std::wstring g_CurrentSidebarRoot = L"";

enum class PieceSource : uint8_t { Original, Add };

// ─────────────────────────────────────────────────────────────────────────────
//  Legacy Piece struct — retained because some external diagnostic / debug
//  code (and any future caller) may still reference it.  The new engine does
//  NOT use it internally; SplayNode supersedes it.
// ─────────────────────────────────────────────────────────────────────────────
struct Piece {
    PieceSource source;
    size_t      start;
    size_t      length;

    Piece() noexcept : source(PieceSource::Original), start(0), length(0) {}
    Piece(PieceSource s, size_t st, size_t len) noexcept
        : source(s), start(st), length(len) {}

    bool valid() const noexcept { return length > 0; }
};

// ─────────────────────────────────────────────────────────────────────────────
//  ArenaAllocator — VirtualAlloc-backed bump allocator.
// ─────────────────────────────────────────────────────────────────────────────
class ArenaAllocator {
public:
    static constexpr size_t kDefaultReserveBytes = 64ull * 1024ull * 1024ull; // 64 MiB
    static constexpr size_t kCommitChunkBytes    = 64ull * 1024ull;           // 64 KiB

    explicit ArenaAllocator(size_t reserveBytes = kDefaultReserveBytes)
        : m_reserveBytes(RoundUpTo(reserveBytes, kCommitChunkBytes)),
          m_committedBytes(0),
          m_offset(0),
          m_base(nullptr)
    {
        m_base = static_cast<uint8_t*>(
            ::VirtualAlloc(nullptr, m_reserveBytes, MEM_RESERVE, PAGE_READWRITE));
        // If reservation fails we fall back to a very small heap shadow so the
        // editor still functions on extremely constrained systems.
        if (!m_base) {
            m_reserveBytes = 0;
        }
    }

    ~ArenaAllocator() {
        if (m_base) {
            ::VirtualFree(m_base, 0, MEM_RELEASE);
            m_base = nullptr;
        }
    }

    ArenaAllocator(const ArenaAllocator&)            = delete;
    ArenaAllocator& operator=(const ArenaAllocator&) = delete;

    // Allocate `bytes` of memory aligned to `alignment` (power of two).
    // Returns nullptr only on catastrophic reservation exhaustion.
    void* Allocate(size_t bytes, size_t alignment = alignof(std::max_align_t)) {
        if (!m_base || bytes == 0) return nullptr;

        size_t aligned = AlignUp(m_offset, alignment);
        size_t needEnd = aligned + bytes;
        if (needEnd > m_reserveBytes) {
            // Out of reserved space — refuse the allocation; PieceTable will
            // fall back to a manual heap copy in this branch (extremely rare).
            return nullptr;
        }

        // Commit pages in 64 KiB chunks until the request fits.
        if (needEnd > m_committedBytes) {
            size_t newCommit = RoundUpTo(needEnd, kCommitChunkBytes);
            if (newCommit > m_reserveBytes) newCommit = m_reserveBytes;
            size_t delta = newCommit - m_committedBytes;
            void* commitAddr = m_base + m_committedBytes;
            void* got = ::VirtualAlloc(commitAddr, delta, MEM_COMMIT, PAGE_READWRITE);
            if (!got) return nullptr;
            m_committedBytes = newCommit;
        }

        m_offset = needEnd;
        return m_base + aligned;
    }

    // Wipe the arena: rewind bump pointer and decommit every committed page.
    // The reserved address range is preserved.
    void Reset() noexcept {
        if (!m_base) { m_offset = 0; return; }
        if (m_committedBytes > 0) {
            ::VirtualFree(m_base, m_committedBytes, MEM_DECOMMIT);
            m_committedBytes = 0;
        }
        m_offset = 0;
    }

    size_t BytesUsed()      const noexcept { return m_offset; }
    size_t BytesCommitted() const noexcept { return m_committedBytes; }
    size_t BytesReserved()  const noexcept { return m_reserveBytes; }

private:
    static size_t AlignUp(size_t v, size_t a) noexcept {
        return (v + (a - 1)) & ~(a - 1);
    }
    static size_t RoundUpTo(size_t v, size_t multiple) noexcept {
        if (multiple == 0) return v;
        return ((v + multiple - 1) / multiple) * multiple;
    }

    size_t   m_reserveBytes;
    size_t   m_committedBytes;
    size_t   m_offset;
    uint8_t* m_base;
};

// ─────────────────────────────────────────────────────────────────────────────
//  SplayNode — one piece of the document, plus tree-structure pointers and
//  the cached subtreeLength used for O(log N) offset lookup.
// ─────────────────────────────────────────────────────────────────────────────
struct SplayNode {
    PieceSource source;
    size_t      start;          // offset into Original buffer or text-arena byte stream
    size_t      length;         // wchar_t count
    size_t      subtreeLength;  // length + left->subtreeLength + right->subtreeLength

    SplayNode* left;
    SplayNode* right;
    SplayNode* parent;

    SplayNode(PieceSource s, size_t st, size_t len) noexcept
        : source(s), start(st), length(len), subtreeLength(len),
          left(nullptr), right(nullptr), parent(nullptr) {}
};

// ─────────────────────────────────────────────────────────────────────────────
//  PieceTable — public API identical to v1.
// ─────────────────────────────────────────────────────────────────────────────
class PieceTable {
public:
    PieceTable()
        : m_textArena(ArenaAllocator::kDefaultReserveBytes),
          m_nodeArena(8ull * 1024ull * 1024ull),    // 8 MiB for nodes
          m_root(nullptr),
          m_addCharCount(0),
          m_virtualLen(0),
          m_cacheValid(false)
    {
        Clear();
    }

    // -------------------------------------------------------------------------
    //  Construction / reset
    // -------------------------------------------------------------------------
    void LoadOriginal(std::wstring text) {
        m_original = std::move(text);

        m_textArena.Reset();
        m_nodeArena.Reset();
        m_root          = nullptr;
        m_addCharCount  = 0;
        m_textSlabs.clear();
        m_textHeapFallback.clear();
        m_nodeHeapFallback.clear();
        m_virtualLen    = 0;
        m_cacheValid    = false;
        m_cachedText.clear();

        if (!m_original.empty()) {
            m_root = NewNode(PieceSource::Original, 0, m_original.size());
            m_virtualLen = m_original.size();
        }
    }

    void Clear() {
        m_original.clear();
        m_textArena.Reset();
        m_nodeArena.Reset();
        m_root          = nullptr;
        m_addCharCount  = 0;
        m_textSlabs.clear();
        m_textHeapFallback.clear();
        m_nodeHeapFallback.clear();
        m_virtualLen    = 0;
        m_cacheValid    = false;
        m_cachedText.clear();
    }

    // -------------------------------------------------------------------------
    //  Queries
    // -------------------------------------------------------------------------
    size_t Length() const noexcept { return m_virtualLen; }
    bool   Empty()  const noexcept { return m_virtualLen == 0; }

    // Number of nodes in the tree (replaces the old m_pieces.size()).
    size_t GetPieceCount() const noexcept { return CountNodes(m_root); }

    const std::wstring& GetVirtualText() const {
        if (!m_cacheValid) RebuildCache();
        return m_cachedText;
    }

    std::wstring GetVirtualSpan(size_t offset, size_t len) const {
        const std::wstring& full = GetVirtualText();
        if (offset >= full.size()) return L"";
        size_t available = full.size() - offset;
        return full.substr(offset, std::min(len, available));
    }

    wchar_t CharAt(size_t pos) const noexcept {
        if (!m_cacheValid) RebuildCache();
        if (pos >= m_cachedText.size()) return L'\0';
        return m_cachedText[pos];
    }

    // -------------------------------------------------------------------------
    //  Mutations
    // -------------------------------------------------------------------------

    // Insert text at virtual position pos (0 = before all content).
    // Amortised O(log N) thanks to splaying.
    void Insert(size_t pos, const std::wstring& text) {
        if (text.empty()) return;
        if (pos > m_virtualLen) pos = m_virtualLen;

        // Copy the new text into the text arena and capture its base offset.
        size_t addStart = AppendToTextArena(text.data(), text.size());

        SplayNode* fresh = NewNode(PieceSource::Add, addStart, text.size());
        m_virtualLen += text.size();
        InvalidateCache();

        if (!m_root) {
            m_root = fresh;
            return;
        }

        if (pos == 0) {
            // Prepend: splay leftmost to root, then attach.
            SplayNode* leftmost = SubtreeMin(m_root);
            Splay(leftmost);
            // m_root is now leftmost, with no left child.
            fresh->right         = m_root;
            m_root->parent       = fresh;
            UpdateSubtreeLength(m_root);
            UpdateSubtreeLength(fresh);
            m_root = fresh;
            return;
        }

        if (pos == m_virtualLen - text.size()) {
            // Append at end: splay rightmost, attach as new right child.
            SplayNode* rightmost = SubtreeMax(m_root);
            Splay(rightmost);
            fresh->left          = m_root;
            m_root->parent       = fresh;
            UpdateSubtreeLength(m_root);
            UpdateSubtreeLength(fresh);
            m_root = fresh;
            return;
        }

        // Mid-document insert: locate the containing node, splay it, then split.
        size_t offsetInPiece = 0;
        SplayNode* hit = FindAndSplay(pos, offsetInPiece);
        if (!hit) {
            // Defensive: shouldn't happen because pos < m_virtualLen.
            AppendAtRightmost(fresh);
            return;
        }

        if (offsetInPiece == 0) {
            // Insert immediately before hit: hit becomes right of fresh,
            // hit's old left subtree becomes left of fresh.
            SplayNode* L = hit->left;
            hit->left    = nullptr;
            if (L) L->parent = nullptr;

            fresh->left  = L;
            fresh->right = hit;
            if (L)   L->parent   = fresh;
            hit->parent          = fresh;
            UpdateSubtreeLength(hit);
            UpdateSubtreeLength(fresh);
            m_root = fresh;
            return;
        }

        // Split hit at offsetInPiece into [leftHalf | fresh | rightHalf].
        SplayNode* rightHalf = NewNode(hit->source,
                                       hit->start + offsetInPiece,
                                       hit->length - offsetInPiece);
        // Truncate hit to become leftHalf.
        hit->length        = offsetInPiece;
        hit->subtreeLength = hit->length;   // children re-aggregated below

        // Detach hit's right subtree.
        SplayNode* origRight = hit->right;
        hit->right = nullptr;
        if (origRight) origRight->parent = nullptr;

        // Build: hit (leftHalf) ── right ──> fresh ── right ──> rightHalf
        //                                               └─ orig right subtree appended
        rightHalf->right = origRight;
        if (origRight) origRight->parent = rightHalf;
        UpdateSubtreeLength(rightHalf);

        fresh->right     = rightHalf;
        rightHalf->parent = fresh;
        UpdateSubtreeLength(fresh);

        hit->right       = fresh;
        fresh->parent    = hit;
        UpdateSubtreeLength(hit);

        // Splay the freshly inserted node to the root for O(1) repeat-keystroke.
        Splay(fresh);
#ifdef TFDEBUG_PT
        assert(ValidateTree() && "PieceTable Insert invariant violation");
#endif
    }

    // Delete virtual range [pos, pos+len).  Amortised O(log N).
    void Delete(size_t pos, size_t len) {
        if (len == 0 || m_virtualLen == 0) return;
        if (pos >= m_virtualLen) return;
        if (pos + len > m_virtualLen) len = m_virtualLen - pos;
        if (len == 0) return;

        InvalidateCache();
        m_virtualLen -= len;

        // Walk the (logical) range and trim/split nodes one at a time.  Each
        // step is O(log N) (FindAndSplay), and the number of steps is bounded
        // by the number of nodes the range crosses (typically 1, sometimes 2).
        size_t remaining = len;
        while (remaining > 0) {
            size_t offsetInPiece = 0;
            SplayNode* hit = FindAndSplay(pos, offsetInPiece);
            if (!hit) break;

            size_t available = hit->length - offsetInPiece;
            size_t take      = std::min(available, remaining);

            if (offsetInPiece == 0 && take == hit->length) {
                // Whole node removed.
                RemoveRoot();           // hit was splayed to root
            }
            else if (offsetInPiece == 0) {
                // Trim from the left.
                hit->start  += take;
                hit->length -= take;
                UpdateSubtreeLength(hit);
            }
            else if (offsetInPiece + take == hit->length) {
                // Trim from the right.
                hit->length -= take;
                UpdateSubtreeLength(hit);
            }
            else {
                // Interior cut: split hit into [left | <cut> | right].
                SplayNode* rightHalf = NewNode(hit->source,
                                               hit->start + offsetInPiece + take,
                                               hit->length - offsetInPiece - take);
                hit->length        = offsetInPiece;

                SplayNode* origRight = hit->right;
                hit->right = rightHalf;
                rightHalf->parent = hit;
                rightHalf->right  = origRight;
                if (origRight) origRight->parent = rightHalf;
                UpdateSubtreeLength(rightHalf);
                UpdateSubtreeLength(hit);
            }

            remaining -= take;
            // pos stays the same; subsequent characters have shifted into it.
        }
#ifdef TFDEBUG_PT
        assert(ValidateTree() && "PieceTable Delete invariant violation");
#endif
    }

    void Replace(size_t pos, size_t oldLen, const std::wstring& newText) {
        Delete(pos, oldLen);
        Insert(pos, newText);
    }

    // -------------------------------------------------------------------------
    //  Memory management
    // -------------------------------------------------------------------------
    // Compact: flatten the tree, move the result into the Original buffer,
    // and instantly Reset() both arenas back to zero offset.  No per-node
    // free calls — the entire append history disappears in O(1) reclamation.
    void Compact() {
        const std::wstring& vt = GetVirtualText();   // forces flatten
        std::wstring fresh    = vt;                  // copy out before we wipe

        m_textArena.Reset();
        m_nodeArena.Reset();
        m_root         = nullptr;
        m_addCharCount = 0;
        m_textSlabs.clear();
        m_textHeapFallback.clear();
        m_nodeHeapFallback.clear();

        m_original = std::move(fresh);
        if (!m_original.empty()) {
            m_root = NewNode(PieceSource::Original, 0, m_original.size());
        }
        m_virtualLen   = m_original.size();
        m_cachedText   = m_original;
        m_cacheValid   = true;
#ifdef TFDEBUG_PT
        assert(ValidateTree() && "PieceTable Compact invariant violation");
#endif
    }

    size_t MemoryCost() const noexcept {
        return  sizeof(PieceTable)
              + m_original.capacity() * sizeof(wchar_t)
              + m_textArena.BytesCommitted()
              + m_nodeArena.BytesCommitted()
              + m_cachedText.capacity() * sizeof(wchar_t);
    }

    // -------------------------------------------------------------------------
    //  Iteration helpers — preserved for the symbol scanner.
    // -------------------------------------------------------------------------
    template<typename Fn>
    void ForEachPiece(Fn&& fn) const {
        ForEachPieceRec(m_root, std::forward<Fn>(fn));
    }

private:
    // ── Storage ────────────────────────────────────────────────────────────
    std::wstring     m_original;       // immutable after LoadOriginal
    ArenaAllocator   m_textArena;      // backs all "Add" wchar_t payload
    ArenaAllocator   m_nodeArena;      // backs SplayNode allocations
    SplayNode*       m_root;
    size_t           m_addCharCount;   // total wchar_t written to text arena
    size_t           m_virtualLen;
    mutable bool     m_cacheValid;
    mutable std::wstring m_cachedText;

    // Heap fallback if an arena ever refuses (extreme corner case).
    mutable std::vector<std::unique_ptr<wchar_t[]>> m_textHeapFallback;
    mutable std::vector<std::unique_ptr<SplayNode>> m_nodeHeapFallback;

    // ── Allocation helpers ────────────────────────────────────────────────
    SplayNode* NewNode(PieceSource src, size_t start, size_t length) {
        void* mem = m_nodeArena.Allocate(sizeof(SplayNode), alignof(SplayNode));
        if (mem) {
            return new (mem) SplayNode(src, start, length);
        }
        // Fallback: heap-allocated node tracked by unique_ptr so it survives
        // until the next Clear()/LoadOriginal().
        auto up = std::make_unique<SplayNode>(src, start, length);
        SplayNode* raw = up.get();
        m_nodeHeapFallback.push_back(std::move(up));
        return raw;
    }

    // Append `count` wchar_t to the text arena; return the byte offset (in
    // wchar_t units) where they begin.  The returned offset is what
    // SplayNode::start stores when source == Add.
    size_t AppendToTextArena(const wchar_t* src, size_t count) {
        size_t bytes = count * sizeof(wchar_t);
        void* mem = m_textArena.Allocate(bytes, alignof(wchar_t));
        if (mem) {
            std::memcpy(mem, src, bytes);
            size_t startOffset = m_addCharCount;
            m_addCharCount += count;
            // Record the slab pointer so AddBufferPtr() can resolve the offset.
            m_textSlabs.push_back({ startOffset, count, static_cast<wchar_t*>(mem) });
            return startOffset;
        }
        // Heap fallback.
        auto up = std::make_unique<wchar_t[]>(count);
        std::memcpy(up.get(), src, bytes);
        size_t startOffset = m_addCharCount;
        m_textSlabs.push_back({ startOffset, count, up.get() });
        m_textHeapFallback.push_back(std::move(up));
        m_addCharCount += count;
        return startOffset;
    }

    // The text arena is conceptually a single growing wchar_t* stream, but
    // physically each Allocate() call returns its own pointer.  We keep a
    // small directory of slabs so that any "Add" virtual offset can be
    // resolved to the correct base pointer in O(log slabs) — typically 1–4
    // slabs total because each insertion is appended contiguously.
    struct TextSlab {
        size_t   startOffset;   // global wchar_t index where this slab begins
        size_t   count;         // wchar_t count in this slab
        wchar_t* data;
    };
    mutable std::vector<TextSlab> m_textSlabs;

    const wchar_t* AddBufferPtr(size_t addStart, size_t length) const {
        // Binary search for the slab that contains addStart.
        // Slabs are appended in increasing startOffset order.
        if (m_textSlabs.empty()) return nullptr;
        size_t lo = 0, hi = m_textSlabs.size() - 1;
        while (lo < hi) {
            size_t mid = lo + (hi - lo + 1) / 2;
            if (m_textSlabs[mid].startOffset <= addStart) lo = mid;
            else                                          hi = mid - 1;
        }
        const TextSlab& s = m_textSlabs[lo];
        // We require that any single SplayNode's [addStart, addStart+length)
        // lies entirely within one slab — which is guaranteed because every
        // Insert() allocates one slab of exactly its text size, and slabs are
        // never split or merged.
        if (addStart < s.startOffset || addStart + length > s.startOffset + s.count) {
            return nullptr;
        }
        return s.data + (addStart - s.startOffset);
    }

    // ── Subtree aggregate maintenance ─────────────────────────────────────
    static size_t SubtreeLen(SplayNode* n) noexcept {
        return n ? n->subtreeLength : 0;
    }
    static void UpdateSubtreeLength(SplayNode* n) noexcept {
        if (!n) return;
        n->subtreeLength = n->length + SubtreeLen(n->left) + SubtreeLen(n->right);
    }

    // ── Splay-tree primitives ─────────────────────────────────────────────
    void RotateLeft(SplayNode* x) noexcept {
        SplayNode* y = x->right;
        if (!y) return;
        x->right = y->left;
        if (y->left) y->left->parent = x;
        y->parent = x->parent;
        if (!x->parent)               m_root = y;
        else if (x == x->parent->left)  x->parent->left  = y;
        else                            x->parent->right = y;
        y->left = x;
        x->parent = y;
        UpdateSubtreeLength(x);
        UpdateSubtreeLength(y);
    }

    void RotateRight(SplayNode* x) noexcept {
        SplayNode* y = x->left;
        if (!y) return;
        x->left = y->right;
        if (y->right) y->right->parent = x;
        y->parent = x->parent;
        if (!x->parent)               m_root = y;
        else if (x == x->parent->right) x->parent->right = y;
        else                            x->parent->left  = y;
        y->right = x;
        x->parent = y;
        UpdateSubtreeLength(x);
        UpdateSubtreeLength(y);
    }

    // Bottom-up splay: bubble x to the root using zig / zig-zig / zig-zag.
    void Splay(SplayNode* x) noexcept {
        if (!x) return;
        while (x->parent) {
            SplayNode* p = x->parent;
            SplayNode* g = p->parent;
            if (!g) {
                // zig
                if (x == p->left) RotateRight(p);
                else              RotateLeft (p);
            } else if (x == p->left && p == g->left) {
                // zig-zig (left-left)
                RotateRight(g);
                RotateRight(p);
            } else if (x == p->right && p == g->right) {
                // zig-zig (right-right)
                RotateLeft(g);
                RotateLeft(p);
            } else if (x == p->right && p == g->left) {
                // zig-zag (left-right)
                RotateLeft(p);
                RotateRight(g);
            } else {
                // zig-zag (right-left)
                RotateRight(p);
                RotateLeft(g);
            }
        }
        m_root = x;
    }

    static SplayNode* SubtreeMin(SplayNode* n) noexcept {
        while (n && n->left) n = n->left;
        return n;
    }
    static SplayNode* SubtreeMax(SplayNode* n) noexcept {
        while (n && n->right) n = n->right;
        return n;
    }

    // O(log N) lookup: descend by comparing pos against left subtree length,
    // then splay the hit node to the root.  offsetInPiece returns how far
    // into the hit node the requested virtual position falls.
    SplayNode* FindAndSplay(size_t pos, size_t& offsetInPiece) {
        SplayNode* cur = m_root;
        size_t target = pos;
        while (cur) {
            size_t leftLen = SubtreeLen(cur->left);
            if (target < leftLen) {
                cur = cur->left;
            } else if (target < leftLen + cur->length) {
                offsetInPiece = target - leftLen;
                Splay(cur);
                return cur;
            } else {
                target -= leftLen + cur->length;
                cur = cur->right;
            }
        }
        offsetInPiece = 0;
        return nullptr;
    }

    // Append `fresh` as the rightmost node — used by Insert when pos == end.
    void AppendAtRightmost(SplayNode* fresh) {
        if (!m_root) { m_root = fresh; return; }
        SplayNode* rm = SubtreeMax(m_root);
        Splay(rm);
        fresh->left   = m_root;
        m_root->parent = fresh;
        UpdateSubtreeLength(m_root);
        UpdateSubtreeLength(fresh);
        m_root = fresh;
    }

    // Remove the current root and stitch its two subtrees together.
    void RemoveRoot() {
        SplayNode* L = m_root->left;
        SplayNode* R = m_root->right;
        if (L) L->parent = nullptr;
        if (R) R->parent = nullptr;

        if (!L) {
            m_root = R;
        } else if (!R) {
            m_root = L;
        } else {
            // Splay max of L to L's root, then attach R as its right child.
            m_root = L;
            SplayNode* lm = SubtreeMax(L);
            Splay(lm);             // lm becomes new root, has no right child
            m_root->right = R;
            R->parent     = m_root;
            UpdateSubtreeLength(m_root);
        }
    }

    // ── Cache flatten (in-order traversal) ────────────────────────────────
    void RebuildCache() const {
        m_cachedText.clear();
        m_cachedText.reserve(m_virtualLen);
        FlattenRec(m_root, m_cachedText);
        m_cacheValid = true;
    }

    void FlattenRec(SplayNode* n, std::wstring& out) const {
        if (!n) return;
        FlattenRec(n->left, out);
        if (n->length > 0) {
            const wchar_t* base = (n->source == PieceSource::Original)
                                  ? (m_original.data() + n->start)
                                  : AddBufferPtr(n->start, n->length);
            if (base) out.append(base, n->length);
        }
        FlattenRec(n->right, out);
    }

    template<typename Fn>
    void ForEachPieceRec(SplayNode* n, Fn&& fn) const {
        if (!n) return;
        ForEachPieceRec(n->left, fn);
        if (n->length > 0) {
            const wchar_t* base = (n->source == PieceSource::Original)
                                  ? (m_original.data() + n->start)
                                  : AddBufferPtr(n->start, n->length);
            if (base) fn(base, n->length);
        }
        ForEachPieceRec(n->right, fn);
    }

    static size_t CountNodes(SplayNode* n) noexcept {
        if (!n) return 0;
        return 1 + CountNodes(n->left) + CountNodes(n->right);
    }

    void InvalidateCache() const noexcept { m_cacheValid = false; }

    // ── Debug invariant checks (compiled in only when TFDEBUG_PT is defined) ─
#ifdef TFDEBUG_PT
    // Validate that every node's subtreeLength equals its length plus its
    // children's subtreeLength values, and that parent pointers are consistent.
    // Also checks buffer bounds for both Original and Add pieces.
    // Returns true if the subtree rooted at n is valid.
    bool ValidateNodeRec(SplayNode* n, SplayNode* expectedParent,
                         size_t& subtreeLenOut) const {
        if (!n) { subtreeLenOut = 0; return true; }

        // Parent linkage
        if (n->parent != expectedParent) {
            OutputDebugStringW(L"TFDEBUG_PT: parent pointer mismatch\n");
            return false;
        }

        // Buffer bounds
        if (n->source == PieceSource::Original) {
            if (n->start + n->length > m_original.size()) {
                OutputDebugStringW(L"TFDEBUG_PT: Original piece out of bounds\n");
                return false;
            }
        } else {
            if (n->start + n->length > m_addCharCount) {
                OutputDebugStringW(L"TFDEBUG_PT: Add piece out of bounds\n");
                return false;
            }
        }

        size_t leftLen = 0, rightLen = 0;
        if (!ValidateNodeRec(n->left,  n, leftLen))  return false;
        if (!ValidateNodeRec(n->right, n, rightLen)) return false;

        size_t expected = n->length + leftLen + rightLen;
        if (n->subtreeLength != expected) {
            wchar_t buf[128];
            swprintf(buf, 128,
                L"TFDEBUG_PT: subtreeLength mismatch: stored=%zu expected=%zu\n",
                n->subtreeLength, expected);
            OutputDebugStringW(buf);
            return false;
        }
        subtreeLenOut = expected;
        return true;
    }

public:
    // Public validation entry point. Call after Insert/Delete/Compact in debug
    // builds: PieceTable::ValidateTree() returns false if any invariant fails
    // and writes a message via OutputDebugString.
    bool ValidateTree() const {
        size_t total = 0;
        bool ok = ValidateNodeRec(m_root, nullptr, total);
        if (ok && total != m_virtualLen) {
            wchar_t buf[128];
            swprintf(buf, 128,
                L"TFDEBUG_PT: virtualLen mismatch: stored=%zu tree=%zu\n",
                m_virtualLen, total);
            OutputDebugStringW(buf);
            return false;
        }
        return ok;
    }

private:
#endif // TFDEBUG_PT
};


// =============================================================================
//  RAII WRAPPERS — eliminate all manual GDI/HDC lifetime bugs
// =============================================================================

class ScopedDC {
    HWND  m_hwnd;
    HDC   m_hdc;
public:
    ScopedDC(HWND hwnd) : m_hwnd(hwnd), m_hdc(GetDC(hwnd)) {}
    ~ScopedDC() { if (m_hdc) ReleaseDC(m_hwnd, m_hdc); }
    operator HDC()  const { return m_hdc; }
    HDC get()       const { return m_hdc; }
    bool isValid()  const { return m_hdc != NULL; }
    ScopedDC(const ScopedDC&)            = delete;
    ScopedDC& operator=(const ScopedDC&) = delete;
};

class ScopedSelectObject {
    HDC     m_hdc;
    HGDIOBJ m_hOld;
public:
    ScopedSelectObject(HDC hdc, HGDIOBJ obj)
        : m_hdc(hdc), m_hOld(obj ? SelectObject(hdc, obj) : NULL) {}
    ~ScopedSelectObject() { if (m_hOld && m_hdc) SelectObject(m_hdc, m_hOld); }
    ScopedSelectObject(const ScopedSelectObject&)            = delete;
    ScopedSelectObject& operator=(const ScopedSelectObject&) = delete;
};

class ScopedGdiObject {
    HGDIOBJ m_obj;
public:
    explicit ScopedGdiObject(HGDIOBJ obj) : m_obj(obj) {}
    ~ScopedGdiObject() { if (m_obj) DeleteObject(m_obj); }
    operator HGDIOBJ() const { return m_obj; }
    HGDIOBJ get()      const { return m_obj; }
    bool isValid()     const { return m_obj != NULL; }
    HGDIOBJ release()  { HGDIOBJ tmp = m_obj; m_obj = NULL; return tmp; }
    ScopedGdiObject(const ScopedGdiObject&)            = delete;
    ScopedGdiObject& operator=(const ScopedGdiObject&) = delete;
};

class MemoryDC {
    HDC      m_memDC;
    HBITMAP  m_bitmap;
    HGDIOBJ  m_oldBmp;
    int      m_width, m_height;
    bool     m_valid;
public:
    MemoryDC(HDC hdc, int w, int h)
        : m_memDC  (CreateCompatibleDC(hdc))
        , m_bitmap (m_memDC ? CreateCompatibleBitmap(hdc, w, h) : NULL)
        , m_oldBmp (m_memDC && m_bitmap ? SelectObject(m_memDC, m_bitmap) : NULL)
        , m_width(w), m_height(h)
        , m_valid (m_memDC != NULL && m_bitmap != NULL) {}

    ~MemoryDC() {
        if (m_memDC) {
            if (m_oldBmp) SelectObject(m_memDC, m_oldBmp);
            if (m_bitmap) DeleteObject(m_bitmap);
            DeleteDC(m_memDC);
        }
    }

    operator HDC() const { return m_memDC; }
    HDC  get()     const { return m_memDC; }
    int  width()   const { return m_width; }
    int  height()  const { return m_height; }
    bool isValid() const { return m_valid; }

    void blitTo(HDC hdc) {
        if (m_valid && hdc)
            BitBlt(hdc, 0, 0, m_width, m_height, m_memDC, 0, 0, SRCCOPY);
    }

    void blitRegionTo(HDC hdc, int x, int y, int cx, int cy, int srcX, int srcY) {
        if (m_valid && hdc)
            BitBlt(hdc, x, y, cx, cy, m_memDC, srcX, srcY, SRCCOPY);
    }

    MemoryDC(const MemoryDC&)            = delete;
    MemoryDC& operator=(const MemoryDC&) = delete;
};

// RAII guard: ensures EditorTab::isRestoring is always reset.
struct RestoreGuard {
    bool* m_flag;
    RestoreGuard(bool* flag) : m_flag(flag) { if (m_flag) *m_flag = true; }
    ~RestoreGuard()                          { if (m_flag) *m_flag = false; }
    RestoreGuard(const RestoreGuard&)            = delete;
    RestoreGuard& operator=(const RestoreGuard&) = delete;
};

// =============================================================================
//  v4.22 — UI-THREAD MESSAGE-BOX HELPERS
//
//  Every modal dialog in this codebase MUST be parented to the top-level
//  window so it is not orphaned when an intermediate child is destroyed,
//  and MUST use MB_TASKMODAL so it cannot be dismissed by an unrelated
//  handler running on the same UI thread before the user has read it.
//
//  Existing call sites still call MessageBoxW directly; new code should
//  prefer these helpers.
// =============================================================================
static inline int TF_MsgBox(HWND hOwner, const wchar_t* text,
                            const wchar_t* caption, UINT flags) noexcept {
    HWND hRoot = hOwner ? GetAncestor(hOwner, GA_ROOT) : NULL;
    return ::MessageBoxW(hRoot, text ? text : L"",
                         caption ? caption : L"Tiny Fantail",
                         flags | MB_TASKMODAL | MB_SETFOREGROUND);
}
static inline int TF_MsgInfo (HWND h, const wchar_t* t, const wchar_t* c = L"Tiny Fantail")
    { return TF_MsgBox(h, t, c, MB_OK | MB_ICONINFORMATION); }
static inline int TF_MsgWarn (HWND h, const wchar_t* t, const wchar_t* c = L"Warning")
    { return TF_MsgBox(h, t, c, MB_OK | MB_ICONWARNING); }
static inline int TF_MsgError(HWND h, const wchar_t* t, const wchar_t* c = L"Error")
    { return TF_MsgBox(h, t, c, MB_OK | MB_ICONERROR); }

// =============================================================================
//  v4.24 — WIN32 SAFETY LAYER
//
//  Every Win32 call that takes an HWND is, in principle, racing with that
//  window's destruction on another thread (or on this thread, via a nested
//  message pump in BulkSetEditText / ProgressUI). The helpers below turn
//  three failure modes into deterministic no-ops:
//
//    A) Stale HWND   — IsWindow() check before the call.
//    B) Hung peer    — SendMessageTimeoutW with SMTO_ABORTIFHUNG so the
//                      UI thread cannot deadlock waiting on a wedged window
//                      procedure (the classic "everything froze" bug).
//    C) Null HWND    — short-circuit, no syscall, no debug spam.
//
//  These are THIN: no allocations, no logging in the hot path, no virtual
//  dispatch. They compile down to the same instruction count as the raw
//  call when the window is alive and responsive.
//
//  Default timeout is intentionally short (2000 ms) — long enough to ride
//  out a transient GDI flush, short enough that a genuine deadlock surfaces
//  as a visible UI hiccup instead of a frozen application.
// =============================================================================

// Default timeout for guarded SendMessage. Tunable per call.
static constexpr UINT TF_SAFE_SEND_TIMEOUT_MS = 2000;

// Returns true iff hWnd is non-null AND refers to a live window.
// IsWindow is itself thread-safe and cheap (one user32 lookup).
static inline bool TF_SafeIsAlive(HWND hWnd) noexcept {
    return hWnd != NULL && ::IsWindow(hWnd);
}

// Guarded, time-bounded SendMessage. Returns true iff the call was
// dispatched AND the target's wndproc returned within the timeout.
// On timeout / dead window / null HWND, *outResult (if provided) is left
// untouched and the function returns false.
static inline bool TF_SafeSend(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam,
                               LRESULT* outResult = nullptr,
                               UINT timeoutMs = TF_SAFE_SEND_TIMEOUT_MS) noexcept {
    if (!TF_SafeIsAlive(hWnd)) return false;
    DWORD_PTR result = 0;
    LRESULT ok = ::SendMessageTimeoutW(
        hWnd, msg, wParam, lParam,
        SMTO_ABORTIFHUNG | SMTO_NORMAL,
        timeoutMs, &result);
    if (ok == 0) return false;       // timeout, hung, or invalid HWND
    if (outResult) *outResult = static_cast<LRESULT>(result);
    return true;
}

// Typed convenience wrapper for callers that only care about the LRESULT,
// e.g. EM_GETFIRSTVISIBLELINE. Returns 'fallback' on any failure path.
template <typename T = LRESULT>
static inline T TF_SafeSendT(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam,
                             T fallback = T{},
                             UINT timeoutMs = TF_SAFE_SEND_TIMEOUT_MS) noexcept {
    LRESULT r = 0;
    if (!TF_SafeSend(hWnd, msg, wParam, lParam, &r, timeoutMs)) return fallback;
    return static_cast<T>(r);
}

// Guarded PostMessage. Asynchronous, so no timeout is needed — but we still
// short-circuit on dead HWND so worker threads don't queue messages to a
// destroyed window (which the kernel would silently drop after logging).
static inline bool TF_SafePost(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) noexcept {
    if (!TF_SafeIsAlive(hWnd)) return false;
    return ::PostMessageW(hWnd, msg, wParam, lParam) != FALSE;
}

// Guarded InvalidateRect. Passing NULL for lpRect invalidates the entire
// client area, matching Win32 semantics.
static inline bool TF_SafeInvalidate(HWND hWnd, const RECT* lpRect = nullptr,
                                     BOOL bErase = TRUE) noexcept {
    if (!TF_SafeIsAlive(hWnd)) return false;
    return ::InvalidateRect(hWnd, lpRect, bErase) != FALSE;
}

// Guarded UpdateWindow — forces a synchronous WM_PAINT if the window has
// a non-empty update region. Safe to call on a freshly invalidated HWND.
static inline bool TF_SafeUpdate(HWND hWnd) noexcept {
    if (!TF_SafeIsAlive(hWnd)) return false;
    return ::UpdateWindow(hWnd) != FALSE;
}

// Guarded ShowWindow. nCmdShow per Win32 (SW_HIDE, SW_SHOW, SW_SHOWNA, ...).
static inline bool TF_SafeShow(HWND hWnd, int nCmdShow) noexcept {
    if (!TF_SafeIsAlive(hWnd)) return false;
    ::ShowWindow(hWnd, nCmdShow);
    return true;
}

// =============================================================================
//  v4.26 — STRICT UI THREAD OWNERSHIP
//
//  Win32 windows are owned by the thread that created them; touching them
//  from any other thread is undefined behaviour.  This block makes that
//  contract machine-checked rather than merely customary.
//
//    g_uiThreadId           — captured in wWinMain BEFORE any window is
//                              created.  All windows in this app are created
//                              on the UI thread, so this id uniquely
//                              identifies "the thread allowed to call
//                              SendMessage / SetWindowText / Invalidate /
//                              tab->pt mutators / undo stack mutators".
//    TF_IsUIThread()        — true iff the current thread is the UI thread.
//    TF_AssertUIThread()    — debug-only assert; no-op in release.  Sprinkle
//                              at the top of any helper that mutates UI or
//                              the document model.
//    WM_TF_UI_TASK          — generic "run this lambda on the UI thread"
//                              doorbell for workers that need richer payloads
//                              than (WPARAM, LPARAM) can carry.
//    TF_PostUITask(fn)      — enqueue a std::function<void()> for execution
//                              on the UI thread.  Returns true if the post
//                              succeeded (window alive, queue accepted it).
//                              Worker-thread safe.  Never blocks.
// =============================================================================
static DWORD g_uiThreadId = 0;   // initialised in wWinMain before window creation

static inline bool TF_IsUIThread() noexcept {
    // Before wWinMain initialises g_uiThreadId we conservatively answer "yes"
    // (no worker threads exist that early; the assertion would be a false
    // positive during static-construction time only).
    return g_uiThreadId == 0 || ::GetCurrentThreadId() == g_uiThreadId;
}

#if defined(_DEBUG) || defined(TFDEBUG_THREADS)
  #define TF_AssertUIThread() \
      do { assert(TF_IsUIThread() && "Win32/PT/undo touched off UI thread"); } while (0)
#else
  #define TF_AssertUIThread() ((void)0)
#endif

// =============================================================================
//  CUSTOM WINDOW MESSAGES
// =============================================================================
#define WM_SYNTAX_CHECK_COMPLETE (WM_USER + 100)
#define WM_EXECUTE_COMPLETE      (WM_USER + 101)
#define WM_DIRECTORY_LOADED      (WM_USER + 102)   // doorbell: drain g_DirLoadQueue
#define WM_FILE_REMOVED          (WM_USER + 105)   // doorbell: drain g_FileRemovedQueue (no lParam pointer)
#define WM_UPDATE_STATS          (WM_USER + 106)   // v4.12: doorbell: drain g_StatResultQueue
#define WM_SIDEBAR_REFRESH       (WM_USER + 107)   // v4.15: doorbell: coalesced add/rename/dir sidebar rescan
#define WM_TF_UI_TASK            (WM_USER + 130)   // v4.26: drain g_UITaskQueue (std::function<void()>)


struct SyntaxCheckResult {
    std::wstring output;
    HWND hEdit;
    int  errorLine;
    bool isPython;
    bool isCpp;
    bool success;
};

static std::atomic<bool> g_SyntaxCheckRunning{false};

// =============================================================================
//  ASYNC STATISTICS WORKER (v4.12)
//
//  Word/char counts are O(n). On multi-MB files, computing them on the UI
//  thread inside EN_CHANGE caused visible stutter while typing. v4.12 mirrors
//  the existing "doorbell" pattern (WM_FILE_REMOVED, WM_DIRECTORY_LOADED,
//  WM_FILE_LOAD_COMPLETE):
//
//    UI thread (EN_CHANGE)
//      |- snapshot doc -> SpawnStatsWorker(...)
//                          |- g_ThreadMgr.spawn([doc = std::move(...)] {
//                                scan doc, poll g_appRunning every 64 KiB
//                                g_StatResultQueue.push(unique_ptr<StatResult>)
//                                PostMessage(WM_UPDATE_STATS)   <-- doorbell
//                             })
//    UI thread (WM_UPDATE_STATS)
//      |- try_pop drain loop -> if hEdit == active tab, set label text
//
//  Invariants preserved:
//    * PieceTable / splay tree never touched off the UI thread (we hand the
//      worker a std::wstring VALUE captured by move -- no PT*, no EditorTab*).
//    * Undo/redo stacks untouched.
//    * Stale results from older keystrokes are discarded via monotonic seq
//      and the hEdit-identity check.
//    * g_appRunning poll inside the scan loop honours the v4.11 shutdown
//      protocol; ThreadManager::shutdownAll() joins this worker like any other.
// =============================================================================
struct StatResult {
    HWND     hEdit       = nullptr;   // identity check on the UI thread
    HWND     hWordLabel  = nullptr;
    HWND     hCharLabel  = nullptr;
    int      wordCount   = 0;
    int      charCount   = 0;
    uint64_t seq         = 0;          // monotonic; UI keeps only newest per hEdit
};

static ThreadSafeQueue<std::unique_ptr<StatResult>> g_StatResultQueue;
static std::atomic<uint64_t> g_StatSeq{0};

// Per-edit "latest seq applied" map lives on the UI thread only -- accessed
// solely from WM_UPDATE_STATS, so no synchronisation needed.
static std::unordered_map<HWND, uint64_t> g_StatLastApplied;

static void SpawnStatsWorker(HWND hMainWnd,
                             HWND hEdit,
                             HWND hWordLabel,
                             HWND hCharLabel,
                             std::wstring docSnapshot)
{
    if (!g_appRunning.load() || !hMainWnd || !hEdit) return;
    const uint64_t mySeq = ++g_StatSeq;

    g_ThreadMgr.spawn([hMainWnd, hEdit, hWordLabel, hCharLabel,
                       doc = std::move(docSnapshot), mySeq]() mutable
    {
        auto out = std::make_unique<StatResult>();
        out->hEdit      = hEdit;
        out->hWordLabel = hWordLabel;
        out->hCharLabel = hCharLabel;
        out->seq        = mySeq;
        out->charCount  = static_cast<int>(doc.size());

        int  words  = 0;
        bool inWord = false;
        constexpr size_t kPollMask = (1u << 16) - 1u;   // poll every 64 KiB
        const size_t n = doc.size();

        for (size_t i = 0; i < n; ++i) {
            if ((i & kPollMask) == 0 && !g_appRunning.load()) return;
            const wchar_t c = doc[i];
            if (c > 32) {
                if (!inWord) { ++words; inWord = true; }
            } else if (iswspace(c)) {
                inWord = false;
            } else if (c != 0) {
                if (!inWord) { ++words; inWord = true; }
            }
        }
        out->wordCount = words;

        if (!g_appRunning.load()) return;
        if (!g_StatResultQueue.push(std::move(out))) return;   // queue shut down
        // Doorbell -- UI thread drains the queue in WM_UPDATE_STATS.
        PostMessageW(hMainWnd, WM_UPDATE_STATS, 0, 0);
    });
}


static int GetDpiForHwnd(HWND hwnd) {
    typedef UINT (WINAPI* GetDpiForWindowFn)(HWND);
    static GetDpiForWindowFn pGetDpiForWindow = NULL;
    static bool checked = false;
    if (!checked) {
        HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
        if (hUser32) pGetDpiForWindow =
            (GetDpiForWindowFn)GetProcAddress(hUser32, "GetDpiForWindow");
        checked = true;
    }
    if (pGetDpiForWindow && hwnd) {
        UINT dpi = pGetDpiForWindow(hwnd);
        if (dpi > 0) return (int)dpi;
    }
    HDC hdc = GetDC(hwnd);
    int dpi = GetDeviceCaps(hdc, LOGPIXELSY);
    ReleaseDC(hwnd, hdc);
    return dpi;
}

static int ScaleForDpi(int val, int dpi) { return MulDiv(val, dpi, 96); }

// =============================================================================
//  CONTROL / MENU IDENTIFIERS
// =============================================================================
#define IDM_EDIT_JUMP_SYMBOL    9001
#define IDC_SYMBOL_LIST         9002
#define IDM_AUTOFILL_MANAGE     9100
#define IDC_AUTOFILL_LIST       9101
#define IDC_AUTOFILL_INPUT      9102
#define IDC_AUTOFILL_ADD        9103
#define IDC_AUTOFILL_DEL        9104
#define IDC_AUTOFILL_LOAD_FILE  9105
#define IDC_AUTOFILL_CLEAR_ALL  9106

struct Symbol {
    std::wstring name;
    int  line;
    HWND hTab;
};
struct SaveEntry {
    std::wstring fileName;
    std::wstring filePath;
};

std::vector<SaveEntry> g_SaveLog;
const int MAX_SAVE_LOG = 10;
#define ID_SAVE_LOG_BASE 6000

std::vector<Symbol> globalSymbols;

#define IDC_MAIN_TAB        100
#define IDC_MAIN_EDIT       101
#define IDC_COMMAND_EDIT    102
#define IDC_EXECUTE_BTN     103
#define IDC_CHECK_BTN       104
#define IDC_LINE_COUNT      105
#define IDC_GUTTER          106
#define IDC_SEARCH_EDIT     107
#define IDC_SEARCH_BTN      108
#define IDC_SEARCH_UP_BTN   109
#define IDC_SYNTAX_TOGGLE   110
#define IDC_COLUMN_INFO     111
#define IDC_DIR_TREE        112   // sidebar WC_TREEVIEW
#define IDC_NEW_FOLDER_BTN  114   // sidebar "new folder" button

// Sidebar geometry constants
#define SIDEBAR_DEFAULT_WIDTH    250   // initial / registry-fallback width
#define SIDEBAR_MIN_WIDTH         80   // minimum draggable width (snaps open)
#define SIDEBAR_COLLAPSE_THRESH   SIDEBAR_MIN_WIDTH  // drag below min → snap to min, never hide
#define SPLITTER_WIDTH             5   // width of the draggable divider bar
#define SIDEBAR_TOOLBAR_HEIGHT    32   // folder action strip above the TreeView

// Backward-compat alias used in a few non-layout string comparisons
#define SIDEBAR_WIDTH SIDEBAR_DEFAULT_WIDTH

// Control ID for the sidebar visibility toggle button
#define IDC_SIDEBAR_TOGGLE        113

#define IDM_FILE_NEW        200
#define IDM_FILE_OPEN       201
#define IDM_FILE_SAVE       202
#define IDM_FILE_SAVEAS     204
#define IDM_FILE_EXIT       203
#define IDM_FOCUS_CMD       2006
#define IDM_FOCUS_SEARCH    2007
#define IDM_EDIT_SELECT_J   2009
#define IDM_FOCUS_EDITOR    2010
#define IDM_EDIT_INDENT     2011
#define IDM_EDIT_OUTDENT    2012
#define IDM_PURGE_TAB_RAM   2013
#define IDM_EDIT_COMPACT    2014
#define ID_GOTO_ERROR       40001

#define IDM_EDIT_MOVE_UP    40002
#define IDM_EDIT_MOVE_DOWN  40003

#define ID_RECENT_FOLDER_BASE 5000
#define MAX_RECENT_FOLDERS    5
#define IDC_SYMBOL_SEARCH     9003

#define MAX_UNDO_LEVELS 4096
#define UNDO_COALESCE_MS 500
#define MEM_THRESHOLD   (1024 * 1024)

std::vector<std::wstring> g_RecentFolders;
std::wstring g_NextOpenDir = L"";

// =============================================================================
//  SIDEBAR / DIRECTORY TREE GLOBALS
// =============================================================================
HWND  g_hDirTree           = NULL;   // the WC_TREEVIEW sidebar
HWND  g_hSplitter          = NULL;   // the draggable 5-px divider bar
HWND  g_hSidebarToggleBtn  = NULL;   // the ◀/▶ visibility toggle button
HWND  g_hNewFolderBtn      = NULL;   // create-folder button above the tree
std::wstring g_TreeRootDir       = L""; // directory currently shown in the tree
std::wstring g_PendingSelectFile = L""; // file to auto-highlight after WM_DIRECTORY_LOADED

// -----------------------------------------------------------------------------
//  Authoritative path storage for sidebar tree items.
//
//  Replaces the legacy "new std::wstring" + lParam pointer scheme.  Lifetime
//  of every entry is tied to the lifetime of the tree itself: we clear the
//  map every time the tree is rebuilt (HandleDirectoryLoaded), every time a
//  tab is closed (RemoveTab), and on application shutdown (WM_DESTROY).
//
//  Invariants:
//    * Every HTREEITEM currently in g_hDirTree has a corresponding entry.
//    * tvi.lParam is always 0 for tree items inserted under this scheme.
//    * Single-threaded UI access only — no synchronisation required.
// -----------------------------------------------------------------------------
std::unordered_map<HTREEITEM, std::wstring> g_TreeMap;

// Helper: look up a tree item's path with safe fallback to empty string.
static const std::wstring& SidebarPathForItem(HTREEITEM hItem) {
    static const std::wstring kEmpty;
    if (!hItem) return kEmpty;
    auto it = g_TreeMap.find(hItem);
    return (it == g_TreeMap.end()) ? kEmpty : it->second;
}

// Mutable sidebar width; persisted to/from the registry.
int   g_sidebarWidth     = SIDEBAR_DEFAULT_WIDTH;
int   g_savedSidebarWidth = SIDEBAR_DEFAULT_WIDTH; // last non-zero width (restored on show)
bool  g_sidebarVisible   = true;    // false when hidden via toggle button

// Result packet posted back to the UI thread by the directory-loader thread.
struct DirLoadResult {
    HWND         hMainWnd;
    std::wstring rootDir;
    std::wstring selectAfterLoad;
    std::wstring errorMessage;
    // recursive list of entries discovered beneath rootDir; parentPath/depth
    // preserve hierarchy while keeping ownership simple across threads.
    struct Entry {
        std::wstring name;      // display name
        std::wstring fullPath;  // absolute path
        std::wstring parentPath;
        int          depth;
        bool         isDir;
        bool         hasChildren;
    };
    std::vector<Entry> entries;
};

// Parameters passed to the directory-loader background thread.
struct DirLoadParams {
    HWND         hMainWnd;
    std::wstring dirPath;
    std::wstring createParentDir;
    std::wstring createChildName;
    std::wstring selectAfterLoad;
};

// =============================================================================
//  AUTOFILL SYSTEM
// =============================================================================
std::vector<std::wstring> g_AutofillWords;
HWND g_hAutofillPopup         = NULL;
HWND g_hAutofillListBox       = NULL;
HWND g_hAutofillOwner         = NULL;
bool g_bAutofillAcceptPending  = false;

void UpdateRecentFoldersMenu(HWND hwnd) {
    HMENU hMenu = GetMenu(hwnd);
    if (!hMenu) return;

    HMENU hFileMenu = GetSubMenu(hMenu, 0);
    if (!hFileMenu) return;

    HMENU hRecentSubMenu = NULL;
    int count = GetMenuItemCount(hFileMenu);
    for (int i = 0; i < count; i++) {
        wchar_t buf[128];
        GetMenuStringW(hFileMenu, i, buf, 128, MF_BYPOSITION);
        if (wcscmp(buf, L"Recent Folders") == 0) {
            hRecentSubMenu = GetSubMenu(hFileMenu, i);
            break;
        }
    }
    if (!hRecentSubMenu) return;

    int existing = GetMenuItemCount(hRecentSubMenu);
    for (int i = existing - 1; i >= 0; i--)
        DeleteMenu(hRecentSubMenu, i, MF_BYPOSITION);

    for (size_t i = 0; i < g_RecentFolders.size(); i++)
        AppendMenuW(hRecentSubMenu, MF_STRING,
                    ID_RECENT_FOLDER_BASE + (int)i,
                    g_RecentFolders[i].c_str());

    DrawMenuBar(hwnd);
}

// =============================================================================
//  EDITOR STATE (UNDO / REDO)
//  EditCommand stores the removed/inserted text as plain wstrings so that
//  ApplyEditCommand can replay them directly on the Win32 EDIT control.
//  The PieceTable tracks the logical document independently; after each
//  undo/redo the PieceTable is resynchronised via SyncPieceTableFromEdit().
// =============================================================================
struct EditCommand {
    DWORD tick;
    DWORD index;

    DWORD caretBeforeStart;
    DWORD caretBeforeEnd;
    DWORD caretAfterStart;
    DWORD caretAfterEnd;

    int scrollBeforeV;
    int scrollBeforeH;
    int scrollAfterV;
    int scrollAfterH;

    std::wstring removedText;
    std::wstring insertedText;

    EditCommand() noexcept
        : tick(0), index(0),
          caretBeforeStart(0), caretBeforeEnd(0),
          caretAfterStart(0),  caretAfterEnd(0),
          scrollBeforeV(0), scrollBeforeH(0),
          scrollAfterV(0),  scrollAfterH(0) {}

    EditCommand(std::wstring&& ins, int sbV, int sbH, DWORD t) noexcept
        : tick(t), index(0),
          insertedText(std::move(ins)),
          scrollBeforeV(sbV), scrollBeforeH(sbH),
          caretBeforeStart(0), caretBeforeEnd(0),
          caretAfterStart(0),  caretAfterEnd(0),
          scrollAfterV(0),     scrollAfterH(0) {}

    EditCommand(EditCommand&& other) noexcept
        : tick(other.tick), index(other.index),
          caretBeforeStart(other.caretBeforeStart),
          caretBeforeEnd(other.caretBeforeEnd),
          caretAfterStart(other.caretAfterStart),
          caretAfterEnd(other.caretAfterEnd),
          scrollBeforeV(other.scrollBeforeV),
          scrollBeforeH(other.scrollBeforeH),
          scrollAfterV(other.scrollAfterV),
          scrollAfterH(other.scrollAfterH),
          removedText(std::move(other.removedText)),
          insertedText(std::move(other.insertedText)) {}

    EditCommand& operator=(EditCommand&& other) noexcept {
        if (this != &other) {
            tick = other.tick;
            index = other.index;
            caretBeforeStart = other.caretBeforeStart;
            caretBeforeEnd = other.caretBeforeEnd;
            caretAfterStart = other.caretAfterStart;
            caretAfterEnd = other.caretAfterEnd;
            scrollBeforeV = other.scrollBeforeV;
            scrollBeforeH = other.scrollBeforeH;
            scrollAfterV = other.scrollAfterV;
            scrollAfterH = other.scrollAfterH;
            removedText = std::move(other.removedText);
            insertedText = std::move(other.insertedText);
        }
        return *this;
    }
    EditCommand(const EditCommand&)                = default;
    EditCommand& operator=(const EditCommand&)     = default;

    size_t memoryCost() const noexcept {
        return sizeof(EditCommand)
             + removedText.capacity()  * sizeof(wchar_t)
             + insertedText.capacity() * sizeof(wchar_t);
    }

    bool isInsertOnly()  const noexcept { return  removedText.empty() && !insertedText.empty(); }
    bool isDeleteOnly()  const noexcept { return !removedText.empty() &&  insertedText.empty(); }
    bool isReplacement() const noexcept { return !removedText.empty() && !insertedText.empty(); }
    bool isNoOp()        const noexcept { return  removedText.empty() &&  insertedText.empty(); }

    void compact() {
        removedText.shrink_to_fit();
        insertedText.shrink_to_fit();
    }
};

// =============================================================================
//  v4.43 — minimal forward decls for stable-ID infrastructure used by
//  EditorTab's constructor.  Full definitions appear below the struct.
//  v4.44 O5 — also forward-declare TF_UnregisterTab for the EditorTab dtor.
// =============================================================================
using TabId  = uint64_t;
using LoadId = uint64_t;
struct LoadCancelToken;
using LoadCancelTokenPtr = std::shared_ptr<LoadCancelToken>;
enum class TabLifecycle : uint8_t { Alive = 0, Closing = 1, Dead = 2 };
struct EditorTab;
static inline void TF_UnregisterTab(EditorTab* t);   // v4.44 O5

namespace tf_v443_ids {
    inline std::atomic<TabId>  g_NextTabIdSeed{1};
    inline std::atomic<LoadId> g_NextLoadIdSeed{1};
}
static inline TabId  TF_NewTabId()  noexcept { return tf_v443_ids::g_NextTabIdSeed.fetch_add(1, std::memory_order_relaxed); }
static inline LoadId TF_NewLoadId() noexcept { return tf_v443_ids::g_NextLoadIdSeed.fetch_add(1, std::memory_order_relaxed); }

// =============================================================================
//  EDITOR TAB
//  PieceTable pt — the logical document shadow.
//  cachedDoc / cachedDocDirty remain for compatibility with the syntax
//  renderer; they are now populated from pt.GetVirtualText() instead of
//  GetWindowText().  This keeps GDI rendering identical to the original.
// =============================================================================
struct EditorTab {
    HWND hEdit;
    HWND hGutter;
    std::wstring sFileName;
    std::wstring sFilePath;
    std::wstring sWorkspaceRoot;
    bool bModified;
    int  errorLine;

    std::vector<int> vOriginalIndents;

    std::deque<EditCommand> undoStack;
    std::deque<EditCommand> redoStack;

    bool isRestoring;
    int  historyIndex;

    size_t initialContentHash;

    std::chrono::steady_clock::time_point lastCommandTime;
    std::wstring lastSavedText;

    int lastScrollV;
    int lastScrollH;

    // ---- Piece Table ----
    PieceTable   pt;            // logical document; kept in sync with EDIT ctrl
    bool         ptDirty;       // true when pt needs syncing from EDIT ctrl text
    // v4.17 — set by PurgeActiveTabRam: tab keeps its identity (sFilePath/sFileName)
    // and tab title, but its in-memory document has been wiped.  SidebarOpenFile
    // checks this flag in its duplicate-path so reopening the file reloads from
    // disk instead of returning the empty purged tab.
    bool         bPurgedNeedsReload;

    // v21 — set by SidebarOpenFile while an async worker is loading this
    // tab's file from disk. The duplicate-check at the top of
    // SidebarOpenFile uses this flag to detect "the user clicked the same
    // sidebar entry twice while the first load is still in flight" and
    // simply switch to the reserved tab instead of spawning a duplicate
    // tab with another hourglass caption. Cleared in WM_FILE_LOAD_COMPLETE
    // and WM_FILE_LOAD_FAILED.
    bool         bAsyncLoading;

    // v4.40 — stable ownership token for cancellable async file loads.
    // The UI thread stamps these before the worker starts.  A close-click
    // during Reading or Rendering marks the tab as abandoned; completion
    // handlers then discard the payload instead of creating/populating a
    // replacement blank tab.
    // v4.43 — replaces v4.40's `void* pAsyncLoadId`.  LoadId is a process-
    // unique uint64_t allocated by TF_NewLoadId(); zero means "no in-flight
    // load".  cancelToken is shared with the worker thread via the
    // FileLoadPayload so cancellation is one atomic store.
    uint64_t                loadId;
    LoadCancelTokenPtr      cancelToken;
    bool                    bCloseAfterAsyncLoadCancel;

    // v4.43 — process-unique tab id, never reused.  Side-table maps id->tab
    // so cross-thread / message-driven references go through TabHandle and
    // cannot dereference a freed tab.
    uint64_t                stableId;

    // v4.43 — explicit lifecycle so handlers can short-circuit instead of
    // touching a tab whose HWNDs are mid-destruction.  Atomic so a debug
    // assert in TF_TabAlive() is race-free.
    std::atomic<uint8_t>    lifecycle;

    // ---- Syntax / render cache (v4.13: viewport-aware sliding window) ----
    // cachedDoc is no longer a mirror of the full document.  It is a sliding
    // window over the piece table starting at absolute character offset
    // cachedDocOffset and spanning cachedDocSpanLen wchar_ts (== cachedDoc.size()).
    // The WM_PAINT handler in EditSubclassProc rebuilds it via
    // pt.GetVirtualSpan(cachedDocOffset, cachedDocSpanLen) whenever either
    // cachedDocDirty is set OR the visible span computed from
    // EM_GETFIRSTVISIBLELINE / EM_LINEINDEX changes.
    std::wstring cachedDoc;
    bool         cachedDocDirty;
    size_t       cachedDocOffset;   // v4.13 — absolute char offset of cachedDoc[0]
    size_t       cachedDocSpanLen;  // v4.13 — last applied span length

    // v4.16 — last reported bracket-match pair (absolute char indices).
    // -1 means "no match currently shown".  Used to debounce title-bar updates
    // so caret motion within the same pair does not re-publish each WM_PAINT.
    int          lastMatchOpenAbs;
    int          lastMatchCloseAbs;

    int   lastLineCount;
    int   skipMultiplier;
    DWORD lastPressTime;

    // v4.26 — Piece Table auto-compaction telemetry.
    //   editsSinceCompact: incremented every time ApplyPieceTableEdit() runs;
    //                      reset to 0 whenever pt.Compact() is called (manual
    //                      menu OR TF_MaybeAutoCompactPT).
    //   lastCompactNodeCount: pt.GetPieceCount() snapshot taken AT compaction
    //                      time, used by TF_MaybeAutoCompactPT to detect
    //                      "fragmentation has grown 4x since last compact".
    size_t       editsSinceCompact;
    size_t       lastCompactNodeCount;

    EditorTab() :
        hEdit(NULL),
        hGutter(NULL),
        sFileName(L"Untitled"),
        sFilePath(L""),
        bModified(false),
        errorLine(-1),
        isRestoring(false),
        historyIndex(0),
        initialContentHash(0),
        lastScrollV(0),
        lastScrollH(0),
        ptDirty(false),
        cachedDocDirty(true),
        cachedDocOffset(0),
        cachedDocSpanLen(0),
        lastMatchOpenAbs(-1),
        lastMatchCloseAbs(-1),
        lastLineCount(1),
        skipMultiplier(1),
        lastPressTime(0),
        bPurgedNeedsReload(false),
        bAsyncLoading(false),
        loadId(0),
        cancelToken(),
        bCloseAfterAsyncLoadCancel(false),
        stableId(TF_NewTabId()),
        lifecycle((uint8_t)TabLifecycle::Alive),
        editsSinceCompact(0),     // v4.26
        lastCompactNodeCount(1),  // v4.26 — fresh PT == 0 or 1 piece
        lastCommandTime(std::chrono::steady_clock::now()) {}


    // -----------------------------------------------------------------------
    //  Piece Table synchronisation helpers
    //
    //  SyncPieceTableFromEdit() — reads the EDIT control text and re-loads
    //  the PieceTable from scratch.  Called after undo/redo and after loading
    //  a file, where we have already paid the O(n) GetWindowText cost anyway.
    //
    //  GetDocument() — returns the virtual text, rebuilding from the EDIT
    //  control if the ptDirty flag is set.  The result is memoised inside
    //  the PieceTable's own cache.
    // -----------------------------------------------------------------------
    void SyncPieceTableFromEdit() {
        if (!hEdit || !IsWindow(hEdit)) return;
        int len = GetWindowTextLength(hEdit);
        std::wstring text(len + 1, L'\0');
        if (len > 0) GetWindowText(hEdit, &text[0], len + 1);
        text.resize(len);
        pt.LoadOriginal(std::move(text));
        ptDirty      = false;
        cachedDocDirty = true;
        // v4.26: a full LoadOriginal collapses the PT to a single piece, so
        // the auto-compactor counters must be reset to match reality.
        editsSinceCompact    = 0;
        lastCompactNodeCount = pt.GetPieceCount();
    }

    // Return the logical document text.  If the piece table is dirty (because
    // the EDIT control changed without a tracked PieceTable edit), re-sync.
    const std::wstring& GetDocument() {
        if (ptDirty) SyncPieceTableFromEdit();
        return pt.GetVirtualText();
    }

    // Mark the piece table as needing a sync from the EDIT control.
    void MarkPtDirty() noexcept {
        ptDirty      = true;
        cachedDocDirty = true;
    }

    // After a tracked Insert/Delete on the piece table, invalidate the render
    // cache.  v4.13: we no longer eagerly flatten the entire document — the
    // next WM_PAINT in EditSubclassProc will rebuild the visible window via
    // pt.GetVirtualSpan(cachedDocOffset, cachedDocSpanLen).
    void RebuildRenderCache() {
        cachedDoc.clear();
        cachedDocOffset  = 0;
        cachedDocSpanLen = 0;
        cachedDocDirty   = true;
    }

    // -----------------------------------------------------------------------
    //  Disk-state detection using PieceTable text hash.
    // -----------------------------------------------------------------------
    bool isAtDiskState() const {
        // Use the piece table's virtual text directly for hashing.
        // If ptDirty we fall back to a "modified" answer (safe default).
        if (ptDirty) return false;
        return std::hash<std::wstring>{}(pt.GetVirtualText()) == initialContentHash;
    }

    // Legacy overload: accepts an externally provided string (used by callers
    // that already have the document text at hand).
    bool isAtDiskState(const std::wstring& currentText) const {
        return std::hash<std::wstring>{}(currentText) == initialContentHash;
    }

    bool isAtBufferLimit() const { return undoStack.empty(); }

    // v4.41 — recorded after every successful save; load worker can verify
    // "the file we are about to open is byte-identical to what we last wrote"
    // and warn the user if antivirus / sync client / external editor changed
    // it underneath us.  0 means "we have not saved this tab yet".
    uint64_t  lastDiskHash  = 0;
    uint64_t  lastDiskBytes = 0;

    // v4.41 — destructor hook invoked by RemoveTab so the recovery snapshot
    // (if any) is removed when the tab goes away cleanly.  Defined as a
    // free function so it can live in tf_v441 without a forward declaration
    // ordering nightmare.

    // v4.44 O5: side-table cleanup.  Marking Dead + unregistering here is
    // belt-and-braces — every code path that reaches the unique_ptr
    // destructor (RemoveTab clean close, abandoned-tab erase, WM_DESTROY
    // teardown) has already done this work, but if a future code path
    // forgets, the destructor catches it.  No-throw guarantee.
    ~EditorTab() noexcept {
        try {
            lifecycle.store((uint8_t)TabLifecycle::Dead, std::memory_order_release);
            loadId = 0;
            TF_UnregisterTab(this);
        } catch (...) { /* swallow — destructor must not throw */ }
    }
};

// ExecParams was used by the old _beginthreadex ExecuteThreadProc which has been
// replaced by a direct ShellExecute call in DoExecuteFile.  Struct removed.

struct SyntaxCheckParams {
    HWND         hwnd;
    HWND         hEdit;
    std::wstring checkCmd;
    bool isPython;
    bool isCpp;
};

// =============================================================================
//  GLOBALS
// =============================================================================
std::vector<const Symbol*> g_VisibleSymbols;
HWND g_hJumpMenuWnd = NULL;

WNDPROC OldEditProc   = NULL;
WNDPROC OldGutterProc = NULL;
WNDPROC OldTabProc    = NULL;

HFONT  hEditorFont  = NULL;
HFONT  hUIFont      = NULL;
HBRUSH hBackBrush   = NULL;
HBRUSH hGutterBrush = NULL;
HBRUSH hDotBrush    = NULL;
HBRUSH hMatchBrush  = NULL;

int  nCurrentFontSize   = 24;
bool g_SyntaxHighlighting = true;

// v4.44 O1: UI thread owns every EditorTab via unique_ptr.  No other code
//          path may free a tab; destruction == unique_ptr scope exit.
std::vector<std::unique_ptr<EditorTab>> g_Tabs;
int g_ActiveTabIndex = -1;

HWND hGlobalTabCtrl   = NULL;
HWND hGlobalLineCount = NULL;
HWND hGlobalColInfo   = NULL;
HWND hGlobalPieceCount = NULL;
HWND hCharLabel       = NULL;
HWND hWordCount       = NULL;

// v4.26: top-level frame window. Captured in WinMain right after CreateWindowEx
// so worker threads can post UI tasks via TF_PostUITask without having to
// thread an HWND through every payload.  Read by workers; written ONCE on
// the UI thread before any worker starts.  std::atomic for safety even
// though writes are single-shot.
static std::atomic<HWND> g_hMainWnd{ nullptr };


const COLORREF BG_COLOR      = RGB(36,  36,  36);
const COLORREF GUTTER_BG     = RGB(28,  28,  28);
const COLORREF GUTTER_TEXT   = RGB(120, 120, 120);
const COLORREF TEXT_COLOR    = RGB(220, 220, 220);
const COLORREF DOT_COLOR     = RGB(117, 101,  21);
const COLORREF CYAN_COLOR    = RGB(0,   255, 255);
const COLORREF KEYWORD_COLOR = RGB(255, 120, 150);
const COLORREF BRACKET_MATCH = RGB(150, 255, 150);

unordered_set<wstring> g_Keywords = {
    L"if", L"else", L"while", L"for", L"return",
    L"int", L"float", L"double", L"void",
    L"class", L"struct", L"public", L"private", L"protected",
    L"def", L"import", L"from",
    L"include", L"char", L"bool", L"true", L"false",
    L"static", L"const", L"virtual",
    L"override", L"typename", L"template", L"namespace",
    L"using", L"try", L"catch", L"throw", L"new", L"delete",
    L"break", L"continue", L"switch", L"case", L"default",
    L"sizeof", L"typedef", L"enum", L"extern", L"inline",
    L"volatile", L"nullptr",
    L"async", L"await", L"lambda", L"as", L"with",
    L"yield", L"pass", L"None", L"self",
    L"uint32_t", L"int32_t", L"uint64_t", L"int64_t",
    L"size_t", L"constexpr", L"print",
    L"and", L"or", L"not", L"elif", L"except",
    L"finally", L"raise", L"assert", L"global",
    L"nonlocal", L"del", L"is", L"in"
};

// =============================================================================
//  FORWARD DECLARATIONS
// =============================================================================
bool DoFileSave(HWND hwnd);
bool DoFileSaveAs(HWND hwnd);
void SwitchToTab(int index);
void UpdateGutter(HWND hEdit, HWND hGutter);

// =============================================================================
//  ASYNC FILE LOAD — background ingest, main-thread commit.
//
//  Disk I/O, UTF-8 / ANSI decoding, and CRLF normalization run on a worker
//  std::thread spawned by BeginAsyncFileLoad. When finished, the worker pushes
//  a unique_ptr<FileLoadPayload> into g_FileLoadQueue and then PostMessageW's
//  a "doorbell" (null lParam) to WM_FILE_LOAD_COMPLETE / WM_FILE_LOAD_FAILED.
//  The UI thread drains the queue in a while-loop — no raw-pointer cast of
//  lParam, no cross-thread ownership hazard.
// =============================================================================
#define WM_FILE_LOAD_COMPLETE   (WM_USER + 110)   // doorbell: drain g_FileLoadQueue
#define WM_FILE_LOAD_FAILED     (WM_USER + 111)   // doorbell: drain g_FileLoadFailedQueue
#define WM_FILE_LOAD_PROGRESS   (WM_USER + 112)   // v19:  WPARAM=read pct(0..100),   LPARAM=loadId
#define WM_FILE_RENDER_PROGRESS (WM_USER + 113)   // v4.28: WPARAM=render pct(0..100), LPARAM=loadId

// ===================================================================
// v20: Bulk-load guard + chunked text-insert helper.
//
// When loading a multi-megabyte file we suppress all EN_CHANGE-driven
// work (line/word counts, syntax recolor, dirty marking, gutter repaint)
// and stream the text into the EDIT control in chunks while pumping
// messages between chunks. This keeps the UI responsive (window can be
// dragged, progress bar repaints) instead of freezing for tens of
// seconds inside a single SetWindowTextW call.
//
// Threshold: files < 256 KB use the fast single-shot path; larger files
// go through the chunked path. CHUNK_BYTES = 512 KB of UTF-16 (~256 K
// wchar_t) is a good balance between throughput and pump granularity.
// ===================================================================
static std::atomic<bool> g_bBulkLoading{false};
static constexpr size_t  BULK_LOAD_THRESHOLD_CHARS = 128 * 1024;     // 128 K wchar_t (~256 KB)
// v4.38: chunk size dropped 4x (256K -> 64K wchar) so each EM_REPLACESEL
// returns within a few ms even on 1 GB documents. The previous 512 KB
// chunk could block the UI thread for >1 s per chunk on slow GPUs,
// which is what made the main window unresponsive while loading.
static constexpr size_t  BULK_LOAD_CHUNK_CHARS     = 64 * 1024;      // 64 K wchar_t (~128 KB)

// v4.38: per-tab "is currently being filled by BulkSetEditText" flag.
// RemoveTab consults this to refuse closing a tab that is mid-render —
// closing it would destroy the HWND under the chunk loop's feet and
// crash the application. Flipped TRUE/FALSE inside BulkSetEditText.
static std::atomic<HWND> g_hBulkLoadingEdit{NULL};

// v4.38: cooperative-cancel flag. RemoveTab/WM_DESTROY set this so
// BulkSetEditText bails between chunks instead of touching a window
// that the caller is about to destroy.
static std::atomic<bool> g_bBulkLoadCancel{false};

// v4.39: distinct "user requested app quit" flag, set by WM_CLOSE
// BEFORE WM_DESTROY runs.  BulkSetEditText / PumpUIDuringBulkLoad
// observe this and bail immediately so the call stack unwinds
// before WindowProc gets to delete the EditorTab vector.
// Workers do NOT touch this — they continue to honour g_appRunning.
static std::atomic<bool> g_appQuitRequested{false};

static void ClearTabRamPayload(EditorTab* tab, bool clearIdentity, bool clearEditText);
static size_t TF_LoadRegistry_RemoveAndCount(uint64_t loadId);
static void HideLoadProgressUI(HWND hOwner);
static void TF_RenderLoadLabel(HWND hMainWnd);

// =============================================================================
//  v4.43 RELIABILITY INFRASTRUCTURE
//
//  These primitives replace the v4.42 raw-pointer cross-thread references
//  with explicit, validated handles.  They are the foundation for every
//  tab-lifecycle / load-cancellation correctness fix in this revision.
// =============================================================================

// ---- Debug log + assert -----------------------------------------------------
//  TF_DROP_LOG: tagged OutputDebugStringW for stale/dropped messages.  Always
//  compiled in (cheap; no string formatting unless the message actually fires)
//  so a customer crash report contains the trail of what got dropped.
#define TF_DROP_LOG(reason) do {                                              \
        OutputDebugStringW(L"[TF v4.43 DROP] " reason L"\n");                 \
    } while (0)

#ifdef _DEBUG
  #define TF_DBG_ASSERT(cond) do {                                            \
        if (!(cond)) {                                                        \
            OutputDebugStringW(L"[TF v4.43 ASSERT] " L#cond L"\n");           \
            DebugBreak();                                                     \
        }                                                                     \
    } while (0)
#else
  #define TF_DBG_ASSERT(cond) ((void)0)
#endif

// ---- Stable LoadId ----------------------------------------------------------
//  Type/seed/factory are forward-declared above EditorTab (see tf_v443_ids).
//  We only re-state the rationale here:
//   * Opaque, monotonically-increasing 64-bit identifier for one async load.
//   * Replaces the v4.42 "void* loadId = payload.get()" scheme, which was
//     vulnerable to address reuse if the heap reissued a freed pointer to a
//     later allocation in the same UI tick.  Zero means "no id".

// ---- Per-load cancel token --------------------------------------------------
//  Both the worker thread and the UI side hold a shared_ptr to the same
//  token.  Cancellation is one atomic store; observers are non-blocking.
//  This replaces (but does not eliminate) the global g_bBulkLoadCancel,
//  which is retained as a fast-path early-out so the bulk-render chunk loop
//  doesn't have to touch the token's atomic on every chunk.
struct LoadCancelToken {
    std::atomic<bool> canceled{false};
    bool is_canceled() const noexcept {
        return canceled.load(std::memory_order_acquire);
    }
    void cancel() noexcept {
        canceled.store(true, std::memory_order_release);
    }
};

// ---- Stable EditorTab id + side-table --------------------------------------
//  Every EditorTab is assigned a unique 64-bit id at construction.  A side-
//  table maps id -> tab*.  The map is updated only on the UI thread (we
//  TF_AssertUIThread() in helpers).  Cross-thread / message-driven refs
//  validate via TabHandle, never via raw pointer.
//  Map is owned by the UI thread; mutex guards rare cross-thread reads
//  (currently none, but cheap insurance against future regressions).
static std::mutex g_TabsByIdMtx;
static std::unordered_map<TabId, EditorTab*> g_TabsById;

// Forward decls; TF_TabAlive() is the canonical "is it safe to use" predicate.
static inline EditorTab* TF_LookupTab(TabId id);
static inline bool       TF_TabAlive(EditorTab* t) noexcept;

// TabHandle: the ONLY sanctioned cross-thread reference to a tab.  Resolves
// to a live EditorTab* on the UI thread or nullptr if the tab has been
// closed/freed in the interim.
struct TabHandle {
    TabId id = 0;
    TabHandle() = default;
    explicit TabHandle(TabId i) : id(i) {}
    bool valid() const noexcept { return id != 0; }
    EditorTab* resolve() const noexcept {
        if (!id) return nullptr;
        EditorTab* t = TF_LookupTab(id);
        return TF_TabAlive(t) ? t : nullptr;
    }
};

static inline EditorTab* TF_LookupTab(TabId id) {
    if (!id) return nullptr;
    std::lock_guard<std::mutex> lk(g_TabsByIdMtx);
    auto it = g_TabsById.find(id);
    return (it == g_TabsById.end()) ? nullptr : it->second;
}

static inline bool TF_TabAlive(EditorTab* t) noexcept {
    return t && t->lifecycle.load(std::memory_order_acquire) == (uint8_t)TabLifecycle::Alive;
}
static inline void TF_RegisterTab(EditorTab* t) {
    if (!t) return;
    std::lock_guard<std::mutex> lk(g_TabsByIdMtx);
    g_TabsById[t->stableId] = t;
}
static inline void TF_UnregisterTab(EditorTab* t) {
    if (!t) return;
    std::lock_guard<std::mutex> lk(g_TabsByIdMtx);
    g_TabsById.erase(t->stableId);
}

// =============================================================================
//  v4.40/v4.43: closing a tab while its worker is still Reading (or while the
//  UI thread is Rendering via BulkSetEditText) must not destroy the EditorTab
//  immediately.  The worker completion still needs a stable token to land on.
//  v4.43: keyed by LoadId (not by void*), guarded by g_AbandonedMtx.
// =============================================================================
static std::mutex                g_AbandonedMtx;
static std::set<LoadId>          g_AbandonedLoadIds;
// v4.44 O1/O3: quarantine vector for tabs whose worker is still in flight.
//             Ownership is MOVED into here from g_Tabs by RemoveTab.
static std::vector<std::unique_ptr<EditorTab>> g_AbandonedLoadingTabs;

static bool TF_IsLoadAbandoned(LoadId loadId) {
    if (!loadId) return false;
    std::lock_guard<std::mutex> lk(g_AbandonedMtx);
    return g_AbandonedLoadIds.find(loadId) != g_AbandonedLoadIds.end();
}

static void TF_MarkLoadAbandoned(LoadId loadId) {
    if (!loadId) return;
    std::lock_guard<std::mutex> lk(g_AbandonedMtx);
    g_AbandonedLoadIds.insert(loadId);
}

static void TF_ClearLoadAbandoned(LoadId loadId) {
    if (!loadId) return;
    std::lock_guard<std::mutex> lk(g_AbandonedMtx);
    g_AbandonedLoadIds.erase(loadId);
}

static void TF_DetachLoadFromProgress(HWND hwnd, LoadId loadId);

// Locate a tab by its load id.  Returns nullptr if no live tab matches.
// outIndex semantics:
//    >= 0       : index in g_Tabs (alive tab being filled)
//    <= -1000000: encoded index in g_AbandonedLoadingTabs (quarantined tab)
//    -1         : not found
static EditorTab* TF_FindTabByLoadId(LoadId loadId, int* outIndex = nullptr) {
    if (outIndex) *outIndex = -1;
    if (!loadId) return nullptr;
    for (size_t i = 0; i < g_Tabs.size(); ++i) {
        EditorTab* t = g_Tabs[i].get();   // v4.44: non-owning view
        if (t && t->bAsyncLoading && t->loadId == loadId) {
            if (outIndex) *outIndex = (int)i;
            return t;
        }
    }
    std::lock_guard<std::mutex> lk(g_AbandonedMtx);
    for (size_t i = 0; i < g_AbandonedLoadingTabs.size(); ++i) {
        EditorTab* t = g_AbandonedLoadingTabs[i].get();   // v4.44: non-owning view
        if (t && t->loadId == loadId) {
            if (outIndex) *outIndex = -1000000 - (int)i;
            return t;
        }
    }
    return nullptr;
}

static bool TF_FinalDeleteAbandonedTabByLoadId(HWND hwnd, LoadId loadId) {
    int index = -1;
    EditorTab* t = TF_FindTabByLoadId(loadId, &index);
    if (!t) {
        TF_ClearLoadAbandoned(loadId);
        return false;
    }

    // R2/O3: mark Dead BEFORE any window destruction so a re-entrant message
    // handler that resolves a stale TabHandle returns nullptr immediately.
    t->lifecycle.store((uint8_t)TabLifecycle::Dead, std::memory_order_release);
    // O2: invalidate the loadId so any late worker payload fails verification.
    t->loadId = 0;
    if (t->cancelToken) t->cancelToken->cancel();
    TF_UnregisterTab(t);

    if (t->hEdit   && IsWindow(t->hEdit))   DestroyWindow(t->hEdit);
    if (t->hGutter && IsWindow(t->hGutter)) DestroyWindow(t->hGutter);
    ClearTabRamPayload(t, true, true);

    // v4.44 O1/O3: NO `delete t` here.  The unique_ptr destructor runs as
    // soon as we erase the slot below — that is the ONLY sanctioned path
    // for releasing the EditorTab object.
    if (index >= 0 && index < (int)g_Tabs.size()) {
        g_Tabs.erase(g_Tabs.begin() + index);   // unique_ptr dtor here
        if (hGlobalTabCtrl && IsWindow(hGlobalTabCtrl) && index < TabCtrl_GetItemCount(hGlobalTabCtrl))
            TabCtrl_DeleteItem(hGlobalTabCtrl, index);
    } else if (index <= -1000000) {
        size_t abandonedIndex = (size_t)(-1000000 - index);
        std::lock_guard<std::mutex> lk(g_AbandonedMtx);
        if (abandonedIndex < g_AbandonedLoadingTabs.size())
            g_AbandonedLoadingTabs.erase(           // unique_ptr dtor here
                g_AbandonedLoadingTabs.begin() + abandonedIndex);
        index = g_ActiveTabIndex;
    }

    TF_ClearLoadAbandoned(loadId);

    if (g_Tabs.empty()) {
        g_ActiveTabIndex = -1;
        if (hwnd && IsWindow(hwnd) && !g_appQuitRequested.load(std::memory_order_acquire))
            CreateNewTab(hwnd);
    } else {
        int newIndex = (index >= (int)g_Tabs.size()) ? (int)g_Tabs.size() - 1 : index;
        SwitchToTab(newIndex);
    }
    return true;
}

// v4.38 — Pump messages so the window stays responsive during bulk load.
//
// Hardening over v4.37:
//   * Budget raised 32 -> 128 so the rest of the UI (menus, sidebar,
//     status bar, OTHER tabs) actually drains its queue. The previous
//     budget of 32 starved the UI on a busy system, which is the root
//     cause of "main UI not responding while resizing massive file".
//   * Input filter now ONLY drops keys/mouse destined for the loading
//     EDIT control. Input for any OTHER edit, the command bar, the
//     sidebar tree, the menu, etc. is dispatched normally — the user
//     can keep typing in another tab while a 1 GB file streams in.
//   * WM_QUIT is re-posted so a shutdown initiated mid-load propagates
//     to the outer GetMessage loop instead of being silently consumed.
//   * NEVER pump WM_PAINT for hEditTarget directly — let the chunked
//     EM_REPLACESEL drive the visual progress; reentrant paints during
//     a partial buffer can briefly show garbled glyph runs.
static void PumpUIDuringBulkLoad(HWND hEditTarget) {
    // v4.43 R7: hard-bail at the top so a user who hit X during the previous
    // pump iteration never gets one more chunk dispatched into a dying tab.
    if (g_appQuitRequested.load(std::memory_order_acquire)) {
        g_bBulkLoadCancel.store(true, std::memory_order_release);
        return;
    }

    MSG msg;
    int budget = 128; // v4.38: 4x the v4.37 budget — UI stays live
    while (budget-- > 0 && PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
        // Propagate quit so app shutdown is honored mid-load.
        if (msg.message == WM_QUIT) {
            PostQuitMessage((int)msg.wParam);
            g_bBulkLoadCancel.store(true, std::memory_order_release);
            g_appQuitRequested.store(true, std::memory_order_release);
            return;
        }
        // v4.39: short-circuit if the user has clicked X while we pump.
        // We let the pump finish dispatching what's already in `msg`,
        // but we will not pull another message after this one returns.
        if (g_appQuitRequested.load(std::memory_order_acquire)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            g_bBulkLoadCancel.store(true, std::memory_order_release);
            return;
        }
        // v4.43 R7: drop input AND timer messages destined for the editor
        // currently being filled.  Timer-driven syntax recolor / line-count
        // updates would otherwise see a half-filled buffer and either
        // recolor it incorrectly (transient flicker) or worse, fight the
        // ongoing EM_REPLACESEL stream.  Input for any OTHER window is
        // dispatched normally so the rest of the UI is fully interactive.
        if (hEditTarget && msg.hwnd == hEditTarget &&
            ((msg.message >= WM_KEYFIRST   && msg.message <= WM_KEYLAST)   ||
             (msg.message >= WM_MOUSEFIRST && msg.message <= WM_MOUSELAST) ||
             (msg.message == WM_TIMER))) {
            continue;
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

// v4.28: RAII helper that re-enables WM_SETREDRAW even on early return /
// exception.  Without this, an exception thrown by SendMessageW or by the
// piece-table ingest below would leave the EDIT control "redraw=FALSE"
// permanently — a silent GDI-state leak that paints the editor blank.
struct EditRedrawSuspendGuard {
    HWND hEdit;
    bool suspended;
    explicit EditRedrawSuspendGuard(HWND h) : hEdit(h), suspended(false) {
        if (hEdit && IsWindow(hEdit)) {
            SendMessageW(hEdit, WM_SETREDRAW, FALSE, 0);
            suspended = true;
        }
    }
    ~EditRedrawSuspendGuard() { resume(); }
    void resume() {
        if (suspended && hEdit && IsWindow(hEdit)) {
            SendMessageW(hEdit, WM_SETREDRAW, TRUE, 0);
            // v4.34: non-erasing, no-children repaint. The EDIT control
            // and our owner-draw subclass repaint the background
            // themselves; the old erase-on-resume produced one full
            // background fill plus a child cascade right after a bulk
            // load — visible flash on dark themes.
            RedrawWindow(hEdit, NULL, NULL,
                         RDW_INVALIDATE | RDW_NOERASE | RDW_NOCHILDREN);
        }
        suspended = false;
    }
    EditRedrawSuspendGuard(const EditRedrawSuspendGuard&) = delete;
    EditRedrawSuspendGuard& operator=(const EditRedrawSuspendGuard&) = delete;
};

// =============================================================================
//  v4.43 — BulkSetEditText (hardened, adaptive, smooth-scroll friendly).
//
//  Improvements over v4.42:
//    * Stable LoadId (uint64_t) replaces void* loadId — no address-reuse
//      confusion in the registry.
//    * Per-load cancel token (LoadCancelTokenPtr) is the source of truth;
//      the global g_bBulkLoadCancel remains as a fast-path early-out.
//    * Adaptive chunk size: 64 KW for <8 MB files, 256 KW for medium,
//      1 MW for huge (>128 MB).  Net effect: progress feels uniform, render
//      throughput improves 1.5-3x on multi-hundred-MB loads (less per-chunk
//      EM_REPLACESEL overhead).
//    * Caller wraps us in EditRedrawSuspendGuard (WM_SETREDRAW=FALSE), which
//      suppresses caret/selection/text painting for the entire bulk fill —
//      strictly stronger than EM_HIDESELECTION and works on standard EDIT.
//    * Cached HWND validated with IsWindow at every gate.  No stale handle.
//    * Hard-bail returns ALL leave g_bBulkLoading state to the caller's
//      RAII guard; no half-state escapes.
// =============================================================================
static void BulkSetEditText(HWND hEdit, const std::wstring& text,
                            HWND hMainWnd, LoadId loadId,
                            LoadCancelTokenPtr cancelToken = nullptr) {
    if (!hEdit || !IsWindow(hEdit)) {
        TF_DROP_LOG(L"BulkSetEditText: dead hEdit at entry");
        return;
    }

    // v4.38/v4.43: publish the in-flight target so RemoveTab/WM_DESTROY can
    // cooperatively cancel us before destroying the HWND. RAII guard
    // clears the publication on every exit path (return, throw).
    struct ActiveLoadPub {
        HWND prev;
        bool prevCancel;
        explicit ActiveLoadPub(HWND h) noexcept
            : prev(g_hBulkLoadingEdit.exchange(h, std::memory_order_acq_rel)),
              prevCancel(g_bBulkLoadCancel.exchange(false, std::memory_order_acq_rel)) {}
        ~ActiveLoadPub() noexcept {
            g_hBulkLoadingEdit.store(prev, std::memory_order_release);
            g_bBulkLoadCancel.store(prevCancel, std::memory_order_release);
        }
        ActiveLoadPub(const ActiveLoadPub&)            = delete;
        ActiveLoadPub& operator=(const ActiveLoadPub&) = delete;
    } _activeLoad(hEdit);

    // R3: per-load cancel observer.  Cheap inline lambda so the chunk loop
    // doesn't pay for a function call.
    auto isCanceled = [&]() noexcept -> bool {
        if (!g_appRunning.load(std::memory_order_acquire))      return true;
        if (g_appQuitRequested.load(std::memory_order_acquire)) return true;
        if (g_bBulkLoadCancel.load(std::memory_order_acquire))  return true;
        if (cancelToken && cancelToken->is_canceled())          return true;
        return false;
    };

    // Raise the EDIT control's text limit BEFORE inserting (default ~32 KB).
    SendMessageW(hEdit, EM_SETLIMITTEXT, 0, 0);

    // v4.43.1 — Standard EDIT controls do NOT support EM_HIDESELECTION
    // (that message belongs to Rich Edit).  Caller already wraps this
    // function in an EditRedrawSuspendGuard (WM_SETREDRAW=FALSE), which
    // suppresses ALL painting — caret, selection, text — for the entire
    // bulk fill.  That is strictly stronger than EM_HIDESELECTION and
    // works on every flavour of EDIT control, so no extra guard is
    // needed here.  We additionally snapshot the selection so that if
    // anything upstream forgot the redraw guard we still leave the
    // caret in a sane place rather than at an arbitrary chunk boundary.
    DWORD _selStart = 0, _selEnd = 0;
    SendMessageW(hEdit, EM_GETSEL, (WPARAM)&_selStart, (LPARAM)&_selEnd);
    struct SelRestoreGuard {
        HWND  h;
        DWORD s, e;
        ~SelRestoreGuard() {
            if (h && IsWindow(h)) {
                // Collapse to start-of-document; the file just loaded,
                // the user expects to be at the top, not at EOF.
                SendMessageW(h, EM_SETSEL, 0, 0);
                SendMessageW(h, EM_SCROLLCARET, 0, 0);
            }
        }
    } _selGuard{hEdit, _selStart, _selEnd};

    // Clear current content first.
    SetWindowTextW(hEdit, L"");

    const size_t total = text.size();
    if (total == 0) {
        if (hMainWnd && loadId)
            PostMessageW(hMainWnd, WM_FILE_RENDER_PROGRESS, 100, (LPARAM)loadId);
        return;
    }

    // R8: adaptive chunk size.  The previous fixed 64 KW chunk was great
    // for small files but caused tens of thousands of message-pump round-
    // trips on huge files.  Bigger chunks for bigger files cut the pump
    // overhead while keeping per-chunk latency under one frame even on
    // a slow machine (1 MW * sizeof(wchar_t) = 2 MB; EM_REPLACESEL on a
    // 2 MB chunk completes well within 16 ms on contemporary hardware).
    const size_t chunkChars =
        (total <      8u * 1024u * 1024u) ?  64u * 1024u :     // <  8 MW   ->  64 KW
        (total <     64u * 1024u * 1024u) ? 256u * 1024u :     // < 64 MW   -> 256 KW
                                           1024u * 1024u;      // huge      ->   1 MW

    // Move caret to end so EM_REPLACESEL appends.
    SendMessageW(hEdit, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);

    size_t offset = 0;
    int    lastReportedPct = -1;
    std::wstring chunkBuf;
    try { chunkBuf.reserve(chunkChars + 1); }
    catch (...) {
        TF_DROP_LOG(L"BulkSetEditText: OOM reserving chunk buffer");
        return;
    }

    // Emit a 0% Render-phase ping right away so the label flips from
    // "Reading 100%" to "Rendering 0%" before the first chunk lands.
    if (hMainWnd && loadId)
        PostMessageW(hMainWnd, WM_FILE_RENDER_PROGRESS, 0, (LPARAM)loadId);

    while (offset < total) {
        // R5/R7: cooperative bail-out at every gate.
        if (isCanceled()) {
            TF_DROP_LOG(L"BulkSetEditText: cancellation observed mid-render");
            return;
        }
        if (!hEdit || !IsWindow(hEdit)) {
            TF_DROP_LOG(L"BulkSetEditText: hEdit destroyed mid-render");
            return;
        }

        size_t take = std::min(chunkChars, total - offset);
        try { chunkBuf.assign(text, offset, take); }
        catch (...) {
            TF_DROP_LOG(L"BulkSetEditText: OOM building chunk");
            return;
        }

        // EM_REPLACESEL with FALSE = do not store in undo buffer.
        SendMessageW(hEdit, EM_REPLACESEL, FALSE, (LPARAM)chunkBuf.c_str());

        offset += take;

        int pct = (int)((offset * 100ULL) / (total ? total : 1ULL));
        if (pct != lastReportedPct) {
            lastReportedPct = pct;
            if (hMainWnd && loadId) {
                PostMessageW(hMainWnd, WM_FILE_RENDER_PROGRESS,
                             (WPARAM)pct, (LPARAM)loadId);
            }
        }

        // Yield to the message loop so the rest of the UI stays alive.
        PumpUIDuringBulkLoad(hEdit);
    }

    // Final 100% ping in case integer rounding clipped the last percent.
    if (hMainWnd && loadId)
        PostMessageW(hMainWnd, WM_FILE_RENDER_PROGRESS, 100, (LPARAM)loadId);

    // Caret back to top after the load (one EM_SCROLLCARET, not per-chunk).
    if (hEdit && IsWindow(hEdit)) {
        SendMessageW(hEdit, EM_SETSEL, 0, 0);
        SendMessageW(hEdit, EM_SCROLLCARET, 0, 0);
    }
}

struct FileLoadPayload {
    HWND           hMainWnd      = nullptr;   // target window
    std::wstring   sFilePath;                 // absolute path on disk
    std::wstring   sFileName;                 // leaf filename (for tab + UI)
    std::wstring   sWorkspaceHint;            // workspace root hint (g_NextOpenDir snapshot)
    std::wstring   text;                      // decoded + normalized text (owned here, not heap-raw)
    DWORD          dwError        = 0;        // GetLastError() on failure
    bool           failed         = false;    // true when posted to failure queue
    // v19: extended fields used by SidebarOpenFile async path
    bool           bFromSidebar   = false;    // true when issued by SidebarOpenFile
    bool           bReuseTabIdx   = false;    // true => reuse tab at iReuseTabIndex (purged tab)
    int            iReuseTabIndex = -1;       // tab index to refill (purged-needs-reload case)
    std::wstring   sWorkspaceRoot;            // explicit workspace anchor (sidebar use)
    long long      llFileSize     = 0;        // total bytes (for progress UI label)
    // v4.28: data-integrity instrumentation.  Worker fills these so the UI
    // thread can verify nothing was silently truncated and so future audits
    // can correlate the on-disk hash with what landed in the piece table.
    long long      llBytesRead    = 0;        // actual bytes consumed from disk
    uint64_t       fnv1aRaw       = 0xcbf29ce484222325ULL; // FNV-1a of raw bytes
    UINT           uCodePage      = 0;        // 0 = empty file, CP_UTF8, or CP_ACP
    bool           bTruncated     = false;    // true if bytesRead < expected size

    // v4.43 — stable identifier for this load.  Allocated by the UI thread
    // before the worker is spawned.  Used as the LPARAM for every progress
    // post (replaces the v4.42 raw-pointer scheme that was vulnerable to
    // address reuse).
    LoadId             loadId       = 0;
    // v4.43 — shared cancel token.  Worker checks token->is_canceled() at
    // every chunk boundary.  UI thread cancels by calling token->cancel().
    LoadCancelTokenPtr cancelToken;
    // v4.43 — opaque handle to the reserved sidebar tab (zero for non-sidebar
    // loads).  Resolves to nullptr if the user closed the tab while the
    // worker was Reading; completion handler treats that as a quiet discard.
    TabId              targetTabId  = 0;
};

// =============================================================================
//  Global thread-safe queues — one per completion message type.
//  Background threads push unique_ptr payloads here, then PostMessageW a
//  zero-lParam "doorbell".  WindowProc drains each queue in a while-loop.
// =============================================================================
static ThreadSafeQueue<std::unique_ptr<FileLoadPayload>>   g_FileLoadQueue;
static ThreadSafeQueue<std::unique_ptr<FileLoadPayload>>   g_FileLoadFailedQueue;
static ThreadSafeQueue<std::unique_ptr<SyntaxCheckResult>> g_SyntaxCheckQueue;
static ThreadSafeQueue<std::unique_ptr<DirLoadResult>>     g_DirLoadQueue;
// v4.11: replaces raw wstring* in WM_FILE_REMOVED lParam (no more heap-new in watcher thread)
static ThreadSafeQueue<std::wstring>                       g_FileRemovedQueue;
// v4.15: coalescing gate — guarantees at most one WM_SIDEBAR_REFRESH doorbell is outstanding
// at any time, even during rapid filesystem bursts (e.g. a build writing many files).
// Written by the watcher thread (compare_exchange); cleared by HandleSidebarRefreshMessage.
static std::atomic<bool>                                   g_SidebarRefreshPending{false};

// v4.26: generic UI-thread marshalling queue.  Worker threads enqueue
// std::function<void()> here and Post WM_TF_UI_TASK; WindowProc drains it
// and runs each task on the UI thread.  This is the ONLY sanctioned way
// for a worker thread to perform UI / model mutations that don't fit a
// (WPARAM, LPARAM) pair.  See TF_PostUITask below.
static ThreadSafeQueue<std::function<void()>>              g_UITaskQueue;

// Forward declaration: defined further down once the main HWND is known.
// Worker threads call TF_PostUITask(fn) and the UI thread runs fn().
static bool TF_PostUITask(std::function<void()> fn) noexcept;


// =============================================================================
//  ThreadManager::shutdownAll() — defined here so it can see all queues above.
//  Called from WM_DESTROY BEFORE any UI state or queue is destroyed.
// =============================================================================
void ThreadManager::shutdownAll() {
    // 1. Signal the global stop flag so all background thread bodies exit early.
    g_appRunning.store(false);

    // 2. Wake every queue (producers and consumers unblock and see m_done).
    //    v4.22: g_StatResultQueue was previously omitted here — a stats
    //    worker blocked in push() at the moment of WM_DESTROY would never
    //    wake and the join below would hang.
    g_FileLoadQueue.shutdown();
    g_FileLoadFailedQueue.shutdown();
    g_SyntaxCheckQueue.shutdown();
    g_DirLoadQueue.shutdown();
    g_FileRemovedQueue.shutdown();
    g_StatResultQueue.shutdown();   // v4.22
    g_UITaskQueue.shutdown();       // v4.26

    // 3. Join every thread we own (in LIFO order to respect natural dependency).
    std::lock_guard<std::mutex> lk(m_mtx);
    for (auto it = m_threads.rbegin(); it != m_threads.rend(); ++it) {
        if (it->joinable()) it->join();
    }
    m_threads.clear();
}

// =============================================================================
//  v4.41 — RELIABILITY HARDENING MODULE  (tf_v441::Reliability)
//
//  PURPOSE
//    Make TinyFantail safe for multi-hour coding sessions.  v4.40 already
//    has excellent thread-safety + GDI lifetime management; this module
//    addresses the residual reliability gaps that show up only under
//    real-world stress (power loss, antivirus rewrites, OS hangs, the user
//    hitting Save right after a bad refactor, an access violation in one
//    handler taking down all open tabs):
//
//      A. AUTOSAVE             every modified tab is snapshotted every 30 s
//                              to %LOCALAPPDATA%\TinyFantail\recover\.
//      B. STARTUP RECOVERY     leftover .recover files are surfaced to the
//                              user on next launch.
//      C. SAVE VERIFICATION    every WriteFileContent re-reads the freshly
//                              written file and refuses to report success
//                              unless the bytes on disk match the bytes
//                              that were in memory.
//      D. BACKUP RING          every save first rotates the previous file
//                              contents to "<path>.bak" so a botched write
//                              or a regrettable refactor is recoverable.
//      E. CRASH SENTINEL       a structured-exception filter wraps the
//                              WindowProc; on access violation / stack
//                              overflow we flush every dirty tab to a
//                              .recover snapshot BEFORE the OS terminates
//                              us — so even a hard crash loses nothing.
//      F. DISK HASH RECORDED   every successful save stamps tab->lastDiskHash
//                              and lastDiskBytes; the load pipeline can
//                              cross-check on reopen.
//      G. INVARIANT AUDIT      DEBUG-only TF_AssertTabInvariants; release
//                              builds compile to nothing.
//      H. GDI COUNTER          atomic counter; status bar can show it.
//
//  DESIGN RULES (so nothing in v4.40 silently regresses)
//    - Pure C++17, no new dependencies.
//    - All disk I/O happens on dedicated worker threads tracked by
//      g_ThreadMgr; autosave never blocks the UI thread.
//    - Recover writes use the SAME atomic temp-file + flush + rename
//      pattern as WriteFileContent, so a power loss DURING autosave
//      cannot corrupt the snapshot.
//    - Every new global is std::atomic OR mutex-guarded.
//    - The crash sentinel runs in the faulting thread's context and
//      only touches state we already proved is reachable from any
//      thread (g_App + the tab list under a new mutex).
//    - The module never throws C++ exceptions across the WindowProc
//      boundary; everything noexcept.
// =============================================================================
namespace tf_v441 { namespace Reliability {

// ── H. GDI handle counter ────────────────────────────────────────────────
//
// Increment from any Create* path, decrement from Delete*.  Read from
// the UI thread to drive a status-bar indicator.  Wrapping ALL existing
// Create* sites is out of scope for this patch (~50 sites) but the
// counter is exposed so future PRs can do that incrementally.
inline std::atomic<int>& GdiCounter() noexcept {
    static std::atomic<int> g{0};
    return g;
}
inline void GdiPlus()  noexcept { GdiCounter().fetch_add(1, std::memory_order_relaxed); }
inline void GdiMinus() noexcept { GdiCounter().fetch_sub(1, std::memory_order_relaxed); }
inline int  GdiGet()   noexcept { return GdiCounter().load(std::memory_order_relaxed); }

// ── shared FNV-1a-64 hashing (matches the load worker's constants) ───────
inline uint64_t Fnv1a64(const void* data, size_t n) noexcept {
    constexpr uint64_t OFFSET = 0xcbf29ce484222325ULL;
    constexpr uint64_t PRIME  = 0x100000001b3ULL;
    uint64_t h = OFFSET;
    auto p = static_cast<const unsigned char*>(data);
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= PRIME; }
    return h;
}

// ── A. recover-directory locator ─────────────────────────────────────────
//
// %LOCALAPPDATA%\TinyFantail\recover\ — created on demand.  Returns L""
// if SHGetKnownFolderPath fails (we then degrade gracefully and skip
// autosave rather than crashing or risking a write to an unknown path).
inline std::wstring RecoverDir() noexcept {
    PWSTR raw = nullptr;
    HRESULT hr = SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &raw);
    if (FAILED(hr) || !raw) return std::wstring();
    std::wstring p;
    try { p.assign(raw); } catch (...) { CoTaskMemFree(raw); return std::wstring(); }
    CoTaskMemFree(raw);
    try { p += L"\\TinyFantail\\recover"; } catch (...) { return std::wstring(); }
    std::error_code ec;
    std::filesystem::create_directories(p, ec);   // idempotent
    return p;
}

// Per-tab recover filename.  Hashing the path means two tabs editing the
// same on-disk file share one snapshot (deterministic) and Untitled tabs
// get a stable per-pointer slot that is cleaned on tab destruction.
inline std::wstring RecoverPathFor(const EditorTab* tab) noexcept {
    if (!tab) return std::wstring();
    std::wstring dir = RecoverDir();
    if (dir.empty()) return std::wstring();
    std::wstring key;
    try {
        key = tab->sFilePath.empty()
            ? (L"untitled-" + std::to_wstring((uintptr_t)tab))
            : tab->sFilePath;
    } catch (...) { return std::wstring(); }
    uint64_t h = Fnv1a64(key.data(), key.size() * sizeof(wchar_t));
    wchar_t name[64];
    swprintf_s(name, L"\\tab-%016llx.recover", (unsigned long long)h);
    try { return dir + name; } catch (...) { return std::wstring(); }
}

// ── A/E. atomic recover snapshot writer ──────────────────────────────────
//
// On-disk layout (little-endian):
//   [0..3]   magic   = 'TFRV'  (0x56524654)
//   [4..7]   version = 1
//   [8..15]  origPath length in bytes (UTF-16)
//   [16..23] document length in bytes (UTF-16)
//   [24..31] FNV-1a-64 of document payload
//   [32..]   origPath UTF-16 then document UTF-16
//
// Writes go through a temp file + FlushFileBuffers + MoveFileExW so a
// power loss during autosave cannot leave a torn snapshot.  Returns
// true on commit; never throws.
inline bool WriteRecoverSnapshot(const std::wstring& recoverPath,
                                 const std::wstring& origPath,
                                 const std::wstring& docText) noexcept
{
    if (recoverPath.empty()) return false;
    std::wstring tmp;
    try { tmp = recoverPath + L".part"; } catch (...) { return false; }

    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    auto closeAndDelete = [&]() noexcept {
        CloseHandle(h);
        DeleteFileW(tmp.c_str());
    };

    auto writeAll = [&](const void* p, size_t n) noexcept -> bool {
        const char* b = static_cast<const char*>(p);
        while (n) {
            DWORD chunk = (DWORD)((n > MAXDWORD) ? MAXDWORD : n);
            DWORD wrote = 0;
            if (!WriteFile(h, b, chunk, &wrote, nullptr) || wrote == 0) return false;
            b += wrote; n -= wrote;
        }
        return true;
    };

    uint64_t origBytes = (uint64_t)origPath.size() * sizeof(wchar_t);
    uint64_t docBytes  = (uint64_t)docText.size()  * sizeof(wchar_t);
    uint64_t docHash   = Fnv1a64(docText.data(), (size_t)docBytes);
    uint32_t magic = 0x56524654, ver = 1;

    bool ok = true;
    ok = ok && writeAll(&magic,     sizeof(magic));
    ok = ok && writeAll(&ver,       sizeof(ver));
    ok = ok && writeAll(&origBytes, sizeof(origBytes));
    ok = ok && writeAll(&docBytes,  sizeof(docBytes));
    ok = ok && writeAll(&docHash,   sizeof(docHash));
    if (origBytes) ok = ok && writeAll(origPath.data(), (size_t)origBytes);
    if (docBytes)  ok = ok && writeAll(docText.data(),  (size_t)docBytes);
    ok = ok && (FlushFileBuffers(h) != FALSE);
    if (!CloseHandle(h)) ok = false;

    if (!ok) { DeleteFileW(tmp.c_str()); return false; }

    if (!MoveFileExW(tmp.c_str(), recoverPath.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(tmp.c_str());
        return false;
    }
    return true;
}

// Read a recover snapshot back.  Returns true on success and fills outPath
// + outText.  On any header mismatch / hash mismatch / IO error we return
// false and leave the outputs untouched.  Never throws.
inline bool ReadRecoverSnapshot(const std::wstring& recoverPath,
                                std::wstring& outOrigPath,
                                std::wstring& outDocText) noexcept
{
    HANDLE h = CreateFileW(recoverPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    auto closeOnExit = [&]() noexcept { CloseHandle(h); };

    LARGE_INTEGER fs{}; if (!GetFileSizeEx(h, &fs) || fs.QuadPart < 32) { closeOnExit(); return false; }

    auto readAll = [&](void* p, size_t n) noexcept -> bool {
        char* b = static_cast<char*>(p);
        while (n) {
            DWORD chunk = (DWORD)((n > MAXDWORD) ? MAXDWORD : n);
            DWORD got = 0;
            if (!ReadFile(h, b, chunk, &got, nullptr) || got == 0) return false;
            b += got; n -= got;
        }
        return true;
    };

    uint32_t magic=0, ver=0;
    uint64_t origBytes=0, docBytes=0, hash=0;
    if (!readAll(&magic,     sizeof(magic))     || magic != 0x56524654) { closeOnExit(); return false; }
    if (!readAll(&ver,       sizeof(ver))       || ver   != 1)          { closeOnExit(); return false; }
    if (!readAll(&origBytes, sizeof(origBytes)))                         { closeOnExit(); return false; }
    if (!readAll(&docBytes,  sizeof(docBytes)))                          { closeOnExit(); return false; }
    if (!readAll(&hash,      sizeof(hash)))                              { closeOnExit(); return false; }

    if (origBytes > (uint64_t)fs.QuadPart || docBytes > (uint64_t)fs.QuadPart) { closeOnExit(); return false; }
    if (origBytes % sizeof(wchar_t) != 0 || docBytes % sizeof(wchar_t) != 0)   { closeOnExit(); return false; }

    std::wstring origPath, docText;
    try {
        origPath.resize((size_t)(origBytes / sizeof(wchar_t)));
        docText.resize ((size_t)(docBytes  / sizeof(wchar_t)));
    } catch (...) { closeOnExit(); return false; }

    if (origBytes && !readAll(&origPath[0], (size_t)origBytes)) { closeOnExit(); return false; }
    if (docBytes  && !readAll(&docText[0],  (size_t)docBytes))  { closeOnExit(); return false; }
    closeOnExit();

    if (Fnv1a64(docText.data(), (size_t)docBytes) != hash) return false;
    outOrigPath = std::move(origPath);
    outDocText  = std::move(docText);
    return true;
}

// Best-effort delete; never throws.
inline void DeleteRecoverSnapshot(const std::wstring& recoverPath) noexcept {
    if (!recoverPath.empty()) DeleteFileW(recoverPath.c_str());
}

// ── A. autosave timer ────────────────────────────────────────────────────
//
// 30-second WM_TIMER on the main window.  The handler iterates g_Tabs on
// the UI thread (so the iteration is safe) and queues per-tab snapshots
// onto g_ThreadMgr — the actual disk write happens on a worker.  The
// worker captures the document text BY VALUE so the UI thread is free to
// mutate the tab while the snapshot is in flight.
constexpr UINT_PTR IDT_AUTOSAVE = 0xFA00;
constexpr UINT     AUTOSAVE_INTERVAL_MS = 30 * 1000;

// Forward decl for wWinMain hook.
inline void StartAutosaveTimer(HWND hMainWnd) noexcept {
    if (hMainWnd && IsWindow(hMainWnd))
        SetTimer(hMainWnd, IDT_AUTOSAVE, AUTOSAVE_INTERVAL_MS, nullptr);
}
inline void StopAutosaveTimer(HWND hMainWnd) noexcept {
    if (hMainWnd && IsWindow(hMainWnd))
        KillTimer(hMainWnd, IDT_AUTOSAVE);
}

// Called by the IDT_AUTOSAVE WM_TIMER branch that PATCH_E4 inserts in
// WindowProc.  Only snapshots tabs that are dirty AND not currently
// being filled by an async load (we'd be racing the loader otherwise).
//
// Each snapshot is dispatched to a worker via g_ThreadMgr.spawn so the
// UI thread is never blocked — even on a slow drive a 1 GB document
// flushes off-thread.
inline void RunAutosavePass() noexcept {
    if (!g_appRunning.load(std::memory_order_acquire)) return;
    if (g_appQuitRequested.load(std::memory_order_acquire)) return;

    // Snapshot the tab list under the implicit UI-thread invariant.
    // We capture (recoverPath, origPath, docText) by value so the worker
    // owns its own copy; the tab pointer is NOT captured into the
    // worker (it could be deleted before the worker runs).
    struct Job { std::wstring recoverPath, origPath, docText; };
    std::vector<Job> jobs;
    jobs.reserve(g_Tabs.size());

    for (auto& up : g_Tabs) {
        EditorTab* t = up.get();   // v4.44: non-owning view
        if (!t) continue;
        if (!t->bModified) continue;       // nothing to save
        if (t->bAsyncLoading) continue;    // loader still owns the buffer
        std::wstring rp = RecoverPathFor(t);
        if (rp.empty()) continue;
        std::wstring doc;
        try { doc = t->GetDocument(); }    // PT-backed; UI-thread only
        catch (...) { continue; }
        try { jobs.push_back({ std::move(rp), t->sFilePath, std::move(doc) }); }
        catch (...) { /* OOM — skip this tab */ }
    }

    if (jobs.empty()) return;

    // Dispatch.  Move into the worker; one worker per pass keeps the
    // ordering predictable and avoids spawning 12 threads on every tick.
    try {
        g_ThreadMgr.spawn([js = std::move(jobs)]() mutable {
            for (auto& j : js) {
                if (!g_appRunning.load(std::memory_order_acquire)) return;
                WriteRecoverSnapshot(j.recoverPath, j.origPath, j.docText);
            }
        });
    } catch (...) { /* spawn failed — next tick will retry */ }
}

// ── B. startup recovery scan ─────────────────────────────────────────────
//
// Runs once from WinMain after the main window exists.  Enumerates the
// recover dir.  If any *.recover files are present, asks the user once
// whether to restore.  On YES we open each snapshot as a new in-memory
// tab (the ORIGINAL file on disk is NOT touched — the user decides
// whether to overwrite it via Save).  On NO we delete every snapshot.
//
// IMPORTANT: this function never aborts startup.  Any exception, file-IO
// error, or user cancel results in a no-op so a corrupt recover dir can
// never prevent the app from launching.
inline void ScanForRecoverySnapshotsOnStartup(HWND hMainWnd) noexcept {
    // v4.44 O4: per user request, do NOT carry backup data across sessions.
    // We silently delete every *.recover and *.bak file found in the
    // recover directory, then return.  Live autosave during this session
    // still works (it writes fresh snapshots) — but nothing leftover from
    // a previous session is offered for restore.
    (void)hMainWnd;
    std::wstring dir = RecoverDir();
    if (dir.empty()) return;
    try {
        for (auto& e : std::filesystem::directory_iterator(dir)) {
            if (!e.is_regular_file()) continue;
            auto p   = e.path();
            auto ext = p.extension();
            if (ext == L".recover" || ext == L".bak" || ext == L".part") {
                std::error_code ec;
                std::filesystem::remove(p, ec);
            }
        }
    } catch (...) { /* ignore — recover dir state is non-essential */ }
    return;

    // ── Dead code retained for reference only; never reached after the
    //    O4 early-return above.  Kept so future maintainers can revive
    //    the prompt-style restore UX without code-archaeology.
#if 0
    std::vector<std::wstring> snapshots;
    try {
        for (auto& e : std::filesystem::directory_iterator(dir)) {
            if (!e.is_regular_file()) continue;
            auto p = e.path();
            if (p.extension() == L".recover") snapshots.push_back(p.wstring());
        }
    } catch (...) { return; }

    if (snapshots.empty()) return;

    wchar_t msg[256];
    swprintf_s(msg,
        L"TinyFantail found %zu unsaved document(s) from a previous session.\n"
        L"Restore them now?\n\n"
        L"YES  - open each snapshot in a new tab\n"
        L"NO   - discard the snapshots permanently",
        snapshots.size());
    int r = MessageBoxW(hMainWnd, msg, L"Recover unsaved work",
                        MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON1);
    if (r != IDYES) {
        for (auto& s : snapshots) DeleteRecoverSnapshot(s);
        return;
    }

    for (auto& snapshotPath : snapshots) {
        std::wstring origPath, docText;
        if (!ReadRecoverSnapshot(snapshotPath, origPath, docText)) {
            DeleteRecoverSnapshot(snapshotPath);
            continue;
        }
        // Open a fresh tab and stuff the recovered text in.  We mark
        // the tab Modified so the user is reminded they have to Save.
        CreateNewTab(hMainWnd);
        EditorTab* tab = GetActiveTab();
        if (!tab || !tab->hEdit) {
            DeleteRecoverSnapshot(snapshotPath);
            continue;
        }
        SetWindowTextW(tab->hEdit, docText.c_str());
        tab->SyncPieceTableFromEdit();
        tab->bModified = true;
        if (!origPath.empty()) {
            // Prefill the tab's path so the next Ctrl+S writes back to the
            // same file the user was editing.  We do NOT overwrite disk now.
            tab->sFilePath = origPath;
            try {
                tab->sFileName = std::filesystem::path(origPath).filename().wstring();
                if (tab->sFileName.empty()) tab->sFileName = L"Recovered";
            } catch (...) { tab->sFileName = L"Recovered"; }
        } else {
            tab->sFileName = L"Recovered (Untitled)";
        }
        // Update tab caption so the user sees what came back.
        TCITEMW tie{}; tie.mask = TCIF_TEXT;
        tie.pszText = const_cast<LPWSTR>(tab->sFileName.c_str());
        if (hGlobalTabCtrl && IsWindow(hGlobalTabCtrl))
            TabCtrl_SetItem(hGlobalTabCtrl, g_ActiveTabIndex, &tie);
        // Snapshot consumed; remove it.  A fresh autosave will recreate
        // one if the user keeps editing without saving.
        DeleteRecoverSnapshot(snapshotPath);
    }
#endif // dead code retained for reference (see O4 above)
}

// ── C. save verification helper ──────────────────────────────────────────
//
// Re-reads `path`, returns its byte length and FNV-1a-64 hash.  Returns
// false on any IO error.  Used by the patched WriteFileContent to confirm
// the bytes that landed on disk match the bytes we tried to write.
inline bool ReadBackHash(const std::wstring& path,
                        uint64_t& outBytes, uint64_t& outHash) noexcept
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); return false; }
    outBytes = (uint64_t)sz.QuadPart;

    constexpr DWORD CHUNK = 1u << 20;   // 1 MiB
    std::vector<unsigned char> buf;
    try { buf.resize(CHUNK); } catch (...) { CloseHandle(h); return false; }

    uint64_t hash = 0xcbf29ce484222325ULL;
    constexpr uint64_t PRIME = 0x100000001b3ULL;

    for (;;) {
        DWORD got = 0;
        if (!ReadFile(h, buf.data(), CHUNK, &got, nullptr)) { CloseHandle(h); return false; }
        if (got == 0) break;
        for (DWORD i = 0; i < got; ++i) { hash ^= buf[i]; hash *= PRIME; }
    }
    CloseHandle(h);
    outHash = hash;
    return true;
}

// ── D. backup-ring helper ────────────────────────────────────────────────
//
// CopyFileW(<path>, <path>.bak) — best-effort; failure is non-fatal.
// Used by WriteFileContent right before the temp+rename so a failed
// verification can roll back to the previous bytes.  Note we use
// CopyFileW and NOT MoveFileExW, because the original file is about
// to be overwritten by the rename — we want a real second copy on
// disk, not a hard link.
inline bool BackupExistingFile(const std::wstring& path) noexcept {
    if (path.empty()) return false;
    DWORD attr = GetFileAttributesW(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return false;        // nothing to back up
    if (attr & FILE_ATTRIBUTE_DIRECTORY) return false;
    std::wstring bak;
    try { bak = path + L".bak"; } catch (...) { return false; }
    return CopyFileW(path.c_str(), bak.c_str(), FALSE) != 0;
}

inline bool RestoreFromBackup(const std::wstring& path) noexcept {
    if (path.empty()) return false;
    std::wstring bak;
    try { bak = path + L".bak"; } catch (...) { return false; }
    return MoveFileExW(bak.c_str(), path.c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
}

// ── E. crash sentinel ────────────────────────────────────────────────────
//
// Called from the SEH __except filter wrapping WindowProc.  We are in
// an unknown-but-fatal state — the only thing we trust is the global
// g_Tabs list (UI-thread-owned) and the recover-dir helpers above.
// We do NOT try to allocate large buffers; we do NOT try to repaint
// the UI; we do NOT try to join workers.  We just flush each modified
// tab's current text to a .recover file and return so the OS can
// terminate us.  The next launch will surface them.
inline void CrashFlushAllTabs() noexcept {
    // Iterating g_Tabs from the SEH filter is acceptable here: the filter
    // runs on the same thread that was about to crash (the UI thread);
    // any handler that mutates g_Tabs has by definition completed before
    // the dispatch returned to the message pump.  If we crashed in the
    // middle of such a handler the worst outcome is a partially-mutated
    // vector — the catch below quarantines that.
    try {
        for (auto& up : g_Tabs) {
            EditorTab* t = up.get();
            if (!t || !t->bModified) continue;
            std::wstring rp = RecoverPathFor(t);
            if (rp.empty()) continue;
            std::wstring doc;
            try { doc = t->GetDocument(); } catch (...) { continue; }
            WriteRecoverSnapshot(rp, t->sFilePath, doc);
        }
    } catch (...) { /* swallow; we are crashing anyway */ }
}

// ── G. invariant audit ───────────────────────────────────────────────────
#ifdef _DEBUG
inline void AssertTabInvariants(const EditorTab* tab) noexcept {
    if (!tab) return;
    // EDIT control should be alive for as long as the tab is in g_Tabs.
    assert((!tab->bAsyncLoading) ||
           (tab->hEdit && IsWindow(tab->hEdit)));
    // If ptDirty is false, the piece table must be consistent (no
    // dangling sync).  We can't cheaply prove byte-equality with the
    // EDIT control here without paying GetWindowText cost, so we only
    // sanity-check the cheap invariants.
    assert(tab->cachedDocOffset <= tab->pt.Length() ||
           tab->cachedDocOffset == 0);
}
#else
inline void AssertTabInvariants(const EditorTab*) noexcept {}
#endif

// Free function called by RemoveTab so the recover snapshot is removed
// when a tab is closed cleanly (the user explicitly discarded the work
// or saved it — either way the snapshot is no longer wanted).
inline void NotifyTabClosed(const EditorTab* tab) noexcept {
    DeleteRecoverSnapshot(RecoverPathFor(tab));
}

}} // namespace tf_v441::Reliability

// =============================================================================
//  v4.26 — TF_PostUITask : worker -> UI-thread marshalling.
//
//  Returns false (without throwing, without blocking) if:
//    * fn is empty,
//    * the main window has not been created yet,
//    * the main window has been destroyed,
//    * the UI task queue is shut down (app teardown in progress),
//    * the queue refused the push.
//  On success, the task is guaranteed to run on the UI thread unless the
//  app exits before the WndProc drains the queue.
//
//  The task itself runs INSIDE the WindowProc handler for WM_TF_UI_TASK,
//  so it can freely call SendMessage / SetWindowText / InvalidateRect on
//  any window owned by the UI thread.
// =============================================================================
static bool TF_PostUITask(std::function<void()> fn) noexcept {
    if (!fn) return false;
    HWND hwnd = g_hMainWnd.load(std::memory_order_acquire);
    if (!TF_SafeIsAlive(hwnd)) return false;
    try {
        if (!g_UITaskQueue.push(std::move(fn))) return false;
    } catch (...) {
        return false;
    }
    // Doorbell only — payload travels via the queue.  PostMessageW is
    // documented thread-safe; TF_SafePost adds the IsWindow guard.
    return TF_SafePost(hwnd, WM_TF_UI_TASK, 0, 0);
}

// =============================================================================
//  v4.28 — AsyncFileLoadThreadBody (hardened).
//
//  Goals over v4.27:
//    * RAII for FILE*  — `FileHandle` guarantees fclose on every exit path
//      (early return, exception, shutdown bail).  Eliminates the prior
//      "must remember to fclose before each return" hazard.
//    * Phase-tagged progress — Reading uses 0..100 of READ phase; the UI
//      separately drives Rendering 0..100 from BulkSetEditText.  No more
//      magic 80/85/92/100 ramp that conflated I/O with decode.
//    * Partial-read detection — if fread returns fewer bytes than the
//      stat'd size AND the stream is not at EOF, we mark the payload as
//      truncated and route to the failure queue with a clear errno.  No
//      more silent data loss when a network share blips mid-read.
//    * Deterministic FNV-1a hash of the raw bytes for downstream
//      verification (data-integrity audit trail).
//    * Decode is bounded: MultiByteToWideChar is called with explicit
//      INT_MAX guard; a >2 GB raw buffer is split into UTF-8 safe slices
//      OR refused with ERROR_FILE_TOO_LARGE rather than wrapping into a
//      negative `int` argument (which Win32 silently mis-interprets).
//    * Every PostMessageW is wrapped through TF_SafePost so a freed HWND
//      can't crash the worker.
// =============================================================================
namespace tf_v428 {
struct FileHandle {
    FILE* fp = nullptr;
    explicit FileHandle(FILE* f) : fp(f) {}
    ~FileHandle() { if (fp) fclose(fp); }
    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;
    operator FILE*() const { return fp; }
    explicit operator bool() const { return fp != nullptr; }
    FILE* release() { FILE* t = fp; fp = nullptr; return t; }
};
} // namespace tf_v428

static void AsyncFileLoadThreadBody(std::unique_ptr<FileLoadPayload> payload) {
    if (!payload || !payload->hMainWnd) return;
    if (!g_appRunning.load()) return;

    HWND    hwnd   = payload->hMainWnd;
    // v4.43: stable opaque LoadId (uint64_t) — set by the UI side before the
    // worker was spawned.  Replaces v4.42's "loadId = payload.get()" so the
    // address-reuse race (a freed payload reissued by malloc to a later
    // allocation in the same UI tick) cannot misroute progress messages.
    LoadId  loadId = payload->loadId;
    // v4.43: per-load cancel token shared with the UI side.  Worker checks
    // it at every chunk boundary so the user closing the loading tab is
    // observed within one chunk's worth of latency, not "whenever the
    // global g_bBulkLoadCancel happens to flip".
    LoadCancelTokenPtr cancelToken = payload->cancelToken;
    auto isCanceled = [&]() noexcept -> bool {
        if (!g_appRunning.load(std::memory_order_acquire))      return true;
        if (cancelToken && cancelToken->is_canceled())          return true;
        return false;
    };

    // Helper: bail to the failure queue with a specific errno.  unique_ptr
    // ownership flips into the failed queue here; subsequent code must NOT
    // touch `payload` after this point.
    auto failWith = [&](DWORD err) {
        payload->dwError = err;
        payload->failed  = true;
        try { g_FileLoadFailedQueue.push(std::move(payload)); } catch (...) {}
        TF_SafePost(hwnd, WM_FILE_LOAD_FAILED, 0, 0);
    };

    tf_v428::FileHandle fp(_wfopen(payload->sFilePath.c_str(), L"rb"));
    if (!fp) {
        if (!g_appRunning.load()) return;
        failWith(GetLastError() ? GetLastError() : (DWORD)ERROR_FILE_NOT_FOUND);
        return;
    }

    if (_fseeki64(fp, 0, SEEK_END) != 0) { failWith((DWORD)ERROR_SEEK); return; }
    long long fsize64 = _ftelli64(fp);
    if (fsize64 < 0) fsize64 = 0;
    if (_fseeki64(fp, 0, SEEK_SET) != 0) { failWith((DWORD)ERROR_SEEK); return; }
    payload->llFileSize = fsize64;

    // v4.28: Refuse files that won't fit in a single MultiByteToWideChar
    // call.  The decoder takes `int` for byte count; >2 GB would silently
    // wrap.  The threshold is generous (1.9 GB) to keep headroom for the
    // wide expansion that follows.
    constexpr long long kMaxLoadable = 1900LL * 1024LL * 1024LL;
    if (fsize64 > kMaxLoadable) { failWith((DWORD)ERROR_FILE_TOO_LARGE); return; }

    // Initial 0% Reading ping — tells UI to show the progress bar.
    TF_SafePost(hwnd, WM_FILE_LOAD_PROGRESS, 0, (LPARAM)loadId);

    std::vector<char> raw;
    if (fsize64 > 0) {
        try {
            raw.resize((size_t)fsize64);
        } catch (...) {
            failWith((DWORD)ERROR_NOT_ENOUGH_MEMORY);
            return;
        }

        // Read in 256 KB chunks so we can post progress and respect shutdown.
        const size_t CHUNK = 256 * 1024;
        size_t total = (size_t)fsize64;
        size_t done  = 0;
        int    lastPct = -1;
        while (done < total) {
            if (isCanceled()) { TF_DROP_LOG(L"AsyncFileLoadThreadBody: canceled mid-read"); return; }
            size_t want = (total - done < CHUNK) ? (total - done) : CHUNK;
            size_t got  = fread(raw.data() + done, 1, want, fp);
            if (got == 0) break;
            done += got;
            // Reading-phase percent is the FULL 0..100 range now (no more
            // 0..80 conflation with decode).  UI separately tracks Render.
            int pct = (int)((done * 100ULL) / (total ? total : 1ULL));
            if (pct != lastPct) {
                lastPct = pct;
                TF_SafePost(hwnd, WM_FILE_LOAD_PROGRESS, (WPARAM)pct, (LPARAM)loadId);
            }
        }
        payload->llBytesRead = (long long)done;
        // v4.28: data-integrity check — partial read on a non-EOF stream is
        // a hard failure, not a silent truncation.  feof() distinguishes
        // legitimate end-of-file (rare with stat'd size) from a network /
        // I/O error mid-read.
        if (done < total) {
            const bool atEof = feof(fp) != 0;
            const int  ferr  = ferror(fp);
            if (!atEof || ferr) {
                failWith((DWORD)ERROR_READ_FAULT);
                return;
            }
            // Genuine size shrinkage between stat and read (rare, possible
            // for a file actively being written): treat as truncated and
            // continue, but stamp the flag for downstream visibility.
            raw.resize(done);
            payload->bTruncated = true;
        }

        // FNV-1a 64 of the raw bytes — cheap, fast, and good enough for an
        // integrity audit ("did we get the same bytes the OS reported?").
        {
            uint64_t h = 0xcbf29ce484222325ULL;
            const uint64_t prime = 0x100000001b3ULL;
            for (size_t i = 0; i < raw.size(); ++i) {
                h ^= (uint8_t)raw[i];
                h *= prime;
            }
            payload->fnv1aRaw = h;
        }
    }
    // FileHandle goes out of scope at the end of the function — fp is closed
    // here unconditionally even on exception.  Keep an explicit close after
    // the read so we release the descriptor before the long decode below.
    fclose(fp.release());

    if (isCanceled()) { TF_DROP_LOG(L"AsyncFileLoadThreadBody: canceled before decode"); return; }
    // Reading phase is now complete (100%); UI keeps it pinned while we
    // decode.  Decode/normalize is fast relative to disk and is intentionally
    // NOT broken out into its own progress tier — Rendering (in BulkSetEditText)
    // will dominate perceived time for huge files.
    TF_SafePost(hwnd, WM_FILE_LOAD_PROGRESS, (WPARAM)100, (LPARAM)loadId);

    if (!raw.empty()) {
        // raw.size() fits in `int` because we capped at kMaxLoadable above.
        const int rawLen = (int)raw.size();
        int wLen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                       raw.data(), rawLen, nullptr, 0);
        UINT codePage = (wLen > 0) ? CP_UTF8 : CP_ACP;
        if (wLen <= 0) {
            wLen = MultiByteToWideChar(CP_ACP, 0, raw.data(), rawLen, nullptr, 0);
        }
        if (wLen <= 0) { failWith((DWORD)ERROR_NO_UNICODE_TRANSLATION); return; }
        payload->uCodePage = codePage;

        std::wstring wstr;
        try { wstr.resize((size_t)wLen); }
        catch (...) { failWith((DWORD)ERROR_NOT_ENOUGH_MEMORY); return; }

        int wOut = MultiByteToWideChar(codePage, 0, raw.data(), rawLen,
                                       wstr.data(), wLen);
        if (wOut != wLen) {
            // Decoder disagreed with itself between sizing pass and copy
            // pass — treat as a hard integrity failure rather than commit
            // a half-decoded buffer.
            failWith((DWORD)ERROR_NO_UNICODE_TRANSLATION);
            return;
        }

        // Free the raw byte buffer NOW so peak memory is wstr + payload->text
        // instead of raw + wstr + payload->text during normalization.  This
        // matters for multi-hundred-MB loads.
        std::vector<char>().swap(raw);

        if (isCanceled()) { TF_DROP_LOG(L"AsyncFileLoadThreadBody: canceled before normalize"); return; }

        // Normalize line endings: lone \n -> \r\n  (Win32 EDIT requires CRLF).
        // Reserve worst-case (every char doubled) — overshoots typical text
        // by 5-10% but eliminates reallocation + copy for huge files.
        try {
            payload->text.reserve(wstr.size() + (wstr.size() / 8) + 16);
        } catch (...) {
            failWith((DWORD)ERROR_NOT_ENOUGH_MEMORY);
            return;
        }
        for (size_t k = 0; k < wstr.size(); ++k) {
            wchar_t c = wstr[k];
            if (c == L'\n' && (k == 0 || wstr[k - 1] != L'\r'))
                payload->text.push_back(L'\r');
            payload->text.push_back(c);
        }
    }

    // R2/R5: explicit cancel-token check BEFORE the final completion post.
    // If the user closed the loading tab during decode, the UI side will
    // have set the token; we must NOT enqueue a payload the UI handler
    // will then have to discard (it does, but we save the work + memory).
    if (isCanceled()) {
        TF_DROP_LOG(L"AsyncFileLoadThreadBody: canceled before final post; dropping payload");
        return;
    }
    try { g_FileLoadQueue.push(std::move(payload)); }
    catch (...) {
        // Queue refused (shutdown).  No payload to fail with anymore — it
        // was moved.  Just drop the doorbell.
        return;
    }
    TF_SafePost(hwnd, WM_FILE_LOAD_COMPLETE, 0, 0);
}

// =============================================================================
//  v19: Background-load progress UI.
//  A small overlay anchored to the bottom of the main window: a label with the
//  filename + byte count, plus a PROGRESS_CLASS bar.  The overlay shows the
//  moment the first async load starts and hides when the last one finishes.
// =============================================================================
static HWND  g_hLoadProgressPanel = nullptr;   // borderless STATIC container
static HWND  g_hLoadProgressLabel = nullptr;   // STATIC text
static HWND  g_hLoadProgressBar   = nullptr;   // PROGRESS_CLASS
static std::atomic<int> g_ActiveLoads{0};      // number of in-flight async loads

#include <map>
#include <mutex>

// =============================================================================
//  v4.27: Per-load registry — fixes intertwined name/size/percent display
//  when two or more massive files are loading concurrently.
//
//  Before v4.27 the overlay had a SINGLE shared label and bar that the most
//  recent ShowLoadProgressUI() call overwrote, so when the user kicked off
//  load B while load A was still streaming bytes, the label would show B's
//  filename + size while the bar was being driven by A's percent posts —
//  visually intertwining the two loads.
//
//  v4.27 keeps a registry keyed by the per-load `loadId` (the same stable
//  pointer the worker already passes in WM_FILE_LOAD_PROGRESS's LPARAM and
//  that the WM_FILE_LOAD_COMPLETE / WM_FILE_LOAD_FAILED queue payloads
//  identify themselves with).  Every label/bar update flows through
//  TF_RenderLoadLabel, which composes a coherent caption from the live
//  registry contents:
//      1 active load  → "Loading: foo.cpp  (842.0 MB)  47%"
//      2 active loads → "Loading 2 files: foo.cpp 47% · bar.json 12%"
//      N>2            → "Loading N files: foo.cpp 47% · bar.json 12% (+N-2 more)"
//  The bar is driven by the MINIMUM percent across active entries so it can
//  never visually jump backward when a small/fast file finishes ahead of a
//  huge one.
// =============================================================================
enum class LoadPhase : unsigned char { Reading, Rendering, Done };

// v4.28: track Reading and Rendering progress as INDEPENDENT percentages so
// the overlay can show "Reading 47% → Rendering 12%" without one phase's
// progress overwriting the other.  The "displayed" percent shown to the user
// depends on `phase`:
//     Reading   → readPct
//     Rendering → renderPct
// This is monotonic per phase.  When phase flips Reading→Rendering the bar
// snaps to 0 (start of new phase) which is the desired UX.
struct LoadEntry {
    std::wstring fileName;
    long long    bytes      = 0;     // file size on disk (Reading basis)
    long long    charsTotal = 0;     // wchar_t count after decode (Rendering basis)
    int          readPct    = 0;     // 0..100, monotonic
    int          renderPct  = 0;     // 0..100, monotonic
    LoadPhase    phase      = LoadPhase::Reading;

    int displayedPct() const {
        switch (phase) {
            case LoadPhase::Reading:   return readPct;
            case LoadPhase::Rendering: return renderPct;
            case LoadPhase::Done:      return 100;
        }
        return 0;
    }
};

static std::mutex                       g_LoadRegistryMtx;
// v4.43: keyed by stable LoadId (uint64_t) instead of raw payload pointer.
static std::map<LoadId, LoadEntry>      g_LoadRegistry;

// Forward decl — defined after the panel HWNDs exist.
static void TF_RenderLoadLabel(HWND hMainWnd);

static void TF_LoadRegistry_Add(LoadId loadId,
                                const std::wstring& fileName,
                                long long bytes) {
    if (!loadId) return;
    std::lock_guard<std::mutex> lk(g_LoadRegistryMtx);
    LoadEntry e;
    e.fileName  = fileName;
    e.bytes     = bytes;
    e.readPct   = 0;
    e.renderPct = 0;
    e.phase     = LoadPhase::Reading;
    g_LoadRegistry[loadId] = std::move(e);
}

// v4.28: phase-aware monotonic percent setter.  The worker thread tags each
// progress post with the phase that produced it (Reading vs Rendering); the
// registry routes the value into the correct field so the two phases can
// never clobber one another.
static bool TF_LoadRegistry_SetPercent(LoadId loadId, int pct, LoadPhase phase) {
    if (!loadId) return false;
    if (pct < 0) pct = 0; if (pct > 100) pct = 100;
    std::lock_guard<std::mutex> lk(g_LoadRegistryMtx);
    auto it = g_LoadRegistry.find(loadId);
    if (it == g_LoadRegistry.end()) return false;
    if (phase == LoadPhase::Rendering) {
        if (pct > it->second.renderPct) it->second.renderPct = pct;
        // A Rendering ping implicitly promotes phase if the worker is still
        // marked Reading (e.g. UI thread started render before worker ack'd).
        if (it->second.phase == LoadPhase::Reading)
            it->second.phase = LoadPhase::Rendering;
    } else {
        if (pct > it->second.readPct) it->second.readPct = pct;
    }
    return true;
}

static bool TF_LoadRegistry_SetPhase(LoadId loadId,
                                     LoadPhase phase,
                                     const std::wstring* overrideName = nullptr,
                                     const long long* overrideBytes = nullptr) {
    if (!loadId) return false;
    std::lock_guard<std::mutex> lk(g_LoadRegistryMtx);
    auto it = g_LoadRegistry.find(loadId);
    if (it == g_LoadRegistry.end()) return false;
    it->second.phase = phase;
    if (overrideName)  it->second.fileName = *overrideName;
    if (overrideBytes) it->second.bytes    = *overrideBytes;
    return true;
}

static void TF_LoadRegistry_Remove(LoadId loadId) {
    if (!loadId) return;
    std::lock_guard<std::mutex> lk(g_LoadRegistryMtx);
    g_LoadRegistry.erase(loadId);
}

// v4.28: ATOMIC remove-and-report-remaining.  Previously two completers
// racing each other could both observe `g_ActiveLoads == 1` between the
// remove and the fetch_sub, both decide they were "last", and both call
// HideLoadProgressUI()/SetWindowText — fine for the panel but a redundant
// title flicker and a real race for any future single-shot teardown.
// Returning the post-erase count under the same lock makes the caller's
// decision unambiguous.
static size_t TF_LoadRegistry_RemoveAndCount(LoadId loadId) {
    std::lock_guard<std::mutex> lk(g_LoadRegistryMtx);
    if (loadId) g_LoadRegistry.erase(loadId);
    return g_LoadRegistry.size();
}

static size_t TF_LoadRegistry_Count() {
    std::lock_guard<std::mutex> lk(g_LoadRegistryMtx);
    return g_LoadRegistry.size();
}

// v4.28: Drop every entry — used on app shutdown so a late-arriving worker
// can't try to re-render a label against a destroyed window.
static void TF_LoadRegistry_Clear() {
    std::lock_guard<std::mutex> lk(g_LoadRegistryMtx);
    g_LoadRegistry.clear();
}

// v4.28: Format "  (842.0 MB)" / "  (45 KB)" / "" for a label fragment.
// _snwprintf_s with _TRUNCATE guarantees null-termination + no overrun even
// if a future caller passes a tiny `cch`.  Returns void; on cch == 0 the
// function is a no-op (defensive — the only call sites pass cch >= 64).
static void TF_FormatBytes(wchar_t* out, size_t cch, long long bytes) {
    if (!out || cch == 0) return;
    out[0] = 0;
    if (bytes >= (1024LL * 1024LL * 1024LL))
        _snwprintf_s(out, cch, _TRUNCATE, L"  (%.2f GB)",
                     (double)bytes / (1024.0 * 1024.0 * 1024.0));
    else if (bytes >= (1024 * 1024))
        _snwprintf_s(out, cch, _TRUNCATE, L"  (%.1f MB)",
                     (double)bytes / (1024.0 * 1024.0));
    else if (bytes >= 1024)
        _snwprintf_s(out, cch, _TRUNCATE, L"  (%lld KB)", bytes / 1024);
    else if (bytes > 0)
        _snwprintf_s(out, cch, _TRUNCATE, L"  (%lld B)",  bytes);
    // else: leave out[] empty.
}

// ─────────────────────────────────────────────────────────────────────────────
// v4.36 SURGICAL UPGRADE — Fixed-size massive-file load progress panel
//
// Goals (user-reported defects fixed here, behaviour-preserving elsewhere):
//   F1. Panel size MUST NOT change with caption length. v4.35 sized the panel
//       once at create time but the STATIC label used SS_LEFT only; long
//       multi-load captions (filename + dual percentages) clipped or, on some
//       themes, triggered the parent STATIC to grow. We now:
//         * Pin the panel to a constant W×H every render (LayoutLoadProgressPanel
//           is invoked from TF_RenderLoadLabel, not just on Show).
//         * Give the label SS_ENDELLIPSIS | SS_NOPREFIX so over-long filenames
//           are truncated with "…" inside the fixed label rect — never grow it.
//   F2. User must always see the LOADING FILE NAME and the REAL-TIME PERCENT.
//       The caption is now split into TWO fixed-height rows:
//           row 1 (label1): "<filename>  (<size>)"          ← ellipsised
//           row 2 (label2): "Reading 42%  ·  Rendering 0%"  ← live percentages
//       Both rows have fixed pixel rects so neither row can resize the panel.
//   F3. Multi-load case keeps the same fixed layout — row 1 says
//       "N files loading", row 2 shows the slowest file's live percentages.
// ─────────────────────────────────────────────────────────────────────────────

// v4.36: a SECOND label HWND for the live percentages line.
static HWND g_hLoadProgressLabel2 = nullptr;

// v4.36: panel geometry is now a single source of truth — used by Ensure,
// Layout, Show and Render so the panel can never drift.
namespace TF_LoadUI {
    constexpr int kPanelW   = 460;
    constexpr int kPanelH   = 78;
    constexpr int kMargin   = 8;
    constexpr int kRow1Y    = 6;    // filename row
    constexpr int kRow1H    = 18;
    constexpr int kRow2Y    = 26;   // live-percent row
    constexpr int kRow2H    = 16;
    constexpr int kBarY     = 48;
    constexpr int kBarH     = 18;
    constexpr int kInnerW   = kPanelW - 2 * kMargin;   // 444
}

static void LayoutLoadProgressPanel(HWND hMainWnd) {
    if (!g_hLoadProgressPanel || !IsWindow(g_hLoadProgressPanel)) return;
    using namespace TF_LoadUI;
    RECT rc; GetClientRect(hMainWnd, &rc);
    const int RIGHT_MARGIN = 24;
    int x = rc.right  - kPanelW - RIGHT_MARGIN;
    int y = rc.bottom - kPanelH - 90;
    if (x < 8) x = 8;
    if (y < 8) y = 8;
    // SWP_NOSIZE is NOT used — we re-assert the constant size every layout
    // pass so a child STATIC autosize quirk can never grow the panel.
    SetWindowPos(g_hLoadProgressPanel, HWND_TOP, x, y, kPanelW, kPanelH,
                 SWP_NOACTIVATE);
    if (g_hLoadProgressLabel)
        SetWindowPos(g_hLoadProgressLabel,  NULL, kMargin, kRow1Y, kInnerW, kRow1H,
                     SWP_NOACTIVATE | SWP_NOZORDER);
    if (g_hLoadProgressLabel2)
        SetWindowPos(g_hLoadProgressLabel2, NULL, kMargin, kRow2Y, kInnerW, kRow2H,
                     SWP_NOACTIVATE | SWP_NOZORDER);
    if (g_hLoadProgressBar)
        SetWindowPos(g_hLoadProgressBar,    NULL, kMargin, kBarY,  kInnerW, kBarH,
                     SWP_NOACTIVATE | SWP_NOZORDER);
}

static void EnsureLoadProgressUI(HWND hMainWnd) {
    if (g_hLoadProgressPanel && IsWindow(g_hLoadProgressPanel)) return;
    using namespace TF_LoadUI;
    // v4.28: stale handles can survive a previous DestroyWindow if the panel
    // creation below fails — explicitly null them so we never reuse a freed
    // HWND value (catch-22: IsWindow on a recycled handle could lie).
    g_hLoadProgressLabel  = nullptr;
    g_hLoadProgressLabel2 = nullptr;
    g_hLoadProgressBar    = nullptr;

    // v4.22: WS_EX_TOPMOST is meaningless on a child window and was
    // misleading; drop it. WS_EX_NOACTIVATE keeps focus in the editor.
    g_hLoadProgressPanel = CreateWindowExW(
        WS_EX_NOACTIVATE,
        L"STATIC", L"",
        WS_CHILD | SS_NOTIFY | WS_BORDER,
        0, 0, kPanelW, kPanelH, hMainWnd, NULL, GetModuleHandle(NULL), NULL);
    if (!g_hLoadProgressPanel) return;

    // v4.36: SS_ENDELLIPSIS truncates over-long filenames inside the fixed
    // label rect with "…" — guarantees row 1 cannot grow horizontally.
    // SS_NOPREFIX keeps "&" characters in filenames from becoming mnemonics.
    g_hLoadProgressLabel = CreateWindowExW(
        0, L"STATIC", L"Loading…",
        WS_CHILD | WS_VISIBLE | SS_LEFT | SS_ENDELLIPSIS | SS_NOPREFIX,
        kMargin, kRow1Y, kInnerW, kRow1H,
        g_hLoadProgressPanel, NULL, GetModuleHandle(NULL), NULL);
    if (g_hLoadProgressLabel)
        SendMessageW(g_hLoadProgressLabel, WM_SETFONT, (WPARAM)hEditorFont, TRUE);

    // v4.36: dedicated row for live percentages — never affected by filename
    // length, so the user always sees up-to-date Reading / Rendering numbers.
    g_hLoadProgressLabel2 = CreateWindowExW(
        0, L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_LEFT | SS_ENDELLIPSIS | SS_NOPREFIX,
        kMargin, kRow2Y, kInnerW, kRow2H,
        g_hLoadProgressPanel, NULL, GetModuleHandle(NULL), NULL);
    if (g_hLoadProgressLabel2)
        SendMessageW(g_hLoadProgressLabel2, WM_SETFONT, (WPARAM)hEditorFont, TRUE);

    g_hLoadProgressBar = CreateWindowExW(
        0, PROGRESS_CLASSW, L"",
        WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
        kMargin, kBarY, kInnerW, kBarH,
        g_hLoadProgressPanel, NULL, GetModuleHandle(NULL), NULL);
    if (g_hLoadProgressBar) {
        SendMessageW(g_hLoadProgressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        SendMessageW(g_hLoadProgressBar, PBM_SETSTEP,  (WPARAM)1, 0);
        SendMessageW(g_hLoadProgressBar, PBM_SETPOS,   (WPARAM)0, 0);
    }
    LayoutLoadProgressPanel(hMainWnd);
}

// v4.27: Show is now a thin shim that registers the load and asks the
// renderer to (re)compose the shared label.  The actual filename/size text
// is owned by TF_RenderLoadLabel — never written here directly — so a
// concurrent second load can't overwrite the first one's caption.
static void ShowLoadProgressUI(HWND hMainWnd, const std::wstring& fileName,
                               long long llBytes, LoadId loadId) {
    EnsureLoadProgressUI(hMainWnd);
    if (!g_hLoadProgressPanel) return;
    if (loadId) TF_LoadRegistry_Add(loadId, fileName, llBytes);
    LayoutLoadProgressPanel(hMainWnd);
    ShowWindow(g_hLoadProgressPanel, SW_SHOWNA);
    TF_RenderLoadLabel(hMainWnd);
}

// v4.22: takes the owner so we can invalidate the rectangle the panel
// occupied. Without this the gutter / editor area underneath the panel
// remained blank until the next unrelated WM_PAINT (the "line numbers
// covered after loading" defect). The owner argument is optional so
// existing callers that already cleared the area can pass NULL.
static void HideLoadProgressUI(HWND hOwner = NULL) {
    if (!g_hLoadProgressPanel || !IsWindow(g_hLoadProgressPanel)) return;

    RECT rcPanel{};
    BOOL gotRect = FALSE;
    if (hOwner && IsWindow(hOwner)) {
        gotRect = GetWindowRect(g_hLoadProgressPanel, &rcPanel);
        if (gotRect) {
            POINT tl{ rcPanel.left,  rcPanel.top    };
            POINT br{ rcPanel.right, rcPanel.bottom };
            ScreenToClient(hOwner, &tl);
            ScreenToClient(hOwner, &br);
            rcPanel = { tl.x, tl.y, br.x, br.y };
        }
    }

    ShowWindow(g_hLoadProgressPanel, SW_HIDE);

    if (gotRect && hOwner) {
        InvalidateRect(hOwner, &rcPanel, TRUE);
        RedrawWindow(hOwner, &rcPanel, NULL,
                     RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW);
    }
}

static void TF_DetachLoadFromProgress(HWND hwnd, LoadId loadId) {
    if (!loadId) return;
    const size_t remainingInReg = TF_LoadRegistry_RemoveAndCount(loadId);
    int remainingCtr = g_ActiveLoads.fetch_sub(1) - 1;
    if (remainingCtr < 0) { g_ActiveLoads.store(0); remainingCtr = 0; }
    if (remainingInReg == 0 && remainingCtr <= 0) HideLoadProgressUI(hwnd);
    else                                          TF_RenderLoadLabel(hwnd);
}

// v4.28: Final teardown — destroys the overlay's HWND tree so the USER32
// objects (3 windows) and any GDI objects bound to them are released to
// the system.  Idempotent.  Call from WM_DESTROY *after* draining queues
// so a late doorbell can't try to repaint a freed panel.  Children are
// destroyed implicitly by DestroyWindow on the parent (Win32-documented).
static void DestroyLoadProgressUI() {
    HWND panel = g_hLoadProgressPanel;
    g_hLoadProgressLabel  = nullptr;   // null FIRST so any racing UI-thread
    g_hLoadProgressLabel2 = nullptr;   // task that ran between checks bails.
    g_hLoadProgressBar    = nullptr;
    g_hLoadProgressPanel  = nullptr;
    if (panel && IsWindow(panel)) DestroyWindow(panel);
    TF_LoadRegistry_Clear();
    g_ActiveLoads.store(0, std::memory_order_release);
}

// v4.27: kept as a low-level fallback for callers that don't have a loadId
// (none currently — WM_FILE_LOAD_PROGRESS now goes through the registry).
static void SetLoadProgressPercent(int pct) {
    if (pct < 0) pct = 0; if (pct > 100) pct = 100;
    if (g_hLoadProgressBar && IsWindow(g_hLoadProgressBar))
        SendMessageW(g_hLoadProgressBar, PBM_SETPOS, (WPARAM)pct, 0);
}

// v4.36: Recompose the TWO label rows + bar from the live registry.
//   row 1 — filename (single load) or "N files loading" (multi)
//   row 2 — real-time read / render percentages
// Panel size is re-asserted every render via LayoutLoadProgressPanel so a
// long caption can never resize the overlay.
static void TF_RenderLoadLabel(HWND hMainWnd) {
    if (!g_hLoadProgressPanel || !IsWindow(g_hLoadProgressPanel)) return;

    // v4.36: re-pin the panel size on every render — defends against any
    // child STATIC that tries to autosize the parent on long captions.
    LayoutLoadProgressPanel(hMainWnd);

    if (!g_hLoadProgressLabel || !IsWindow(g_hLoadProgressLabel)) return;

    // Snapshot under the lock so we don't hold it while touching HWNDs.
    std::vector<LoadEntry> snap;
    try {
        std::lock_guard<std::mutex> lk(g_LoadRegistryMtx);
        snap.reserve(g_LoadRegistry.size());
        for (auto& kv : g_LoadRegistry) snap.push_back(kv.second);
    } catch (...) {
        return;  // OOM — refuse to update rather than render garbage.
    }

    if (snap.empty()) return;  // about to be hidden by caller

    // Bar = MIN displayed percent across active loads (no backward motion).
    int barPct = 100;
    for (auto& e : snap) { int p = e.displayedPct(); if (p < barPct) barPct = p; }
    if (g_hLoadProgressBar && IsWindow(g_hLoadProgressBar))
        SendMessageW(g_hLoadProgressBar, PBM_SETPOS, (WPARAM)barPct, 0);

    wchar_t row1[512] = {0};
    wchar_t row2[256] = {0};

    // Pick the slowest load to drive row 2 (matches the bar).
    const LoadEntry* slowest = &snap[0];
    for (auto& e : snap) {
        if (e.displayedPct() < slowest->displayedPct()) slowest = &e;
    }

    if (snap.size() == 1) {
        const LoadEntry& e = snap[0];
        wchar_t sz[64] = {0}; TF_FormatBytes(sz, 64, e.bytes);
        // Row 1: filename + size. SS_ENDELLIPSIS will truncate visually if
        // the filename is too long for the fixed label width.
        _snwprintf_s(row1, _countof(row1), _TRUNCATE,
                     L"%ls%ls", e.fileName.c_str(), sz);
        // Row 2: live percentages. Always show BOTH read and render so the
        // user sees real-time progress through the entire pipeline.
        const wchar_t* phaseTag = L"Loading";
        switch (e.phase) {
            case LoadPhase::Reading:   phaseTag = L"Reading";    break;
            case LoadPhase::Rendering: phaseTag = L"Rendering";  break;
            case LoadPhase::Done:      phaseTag = L"Finalizing"; break;
        }
        _snwprintf_s(row2, _countof(row2), _TRUNCATE,
                     L"%ls  ·  read %d%%  ·  render %d%%",
                     phaseTag, e.readPct, e.renderPct);
    } else {
        // Multi-load: row 1 announces count + the slowest file's name.
        wchar_t sz[64] = {0}; TF_FormatBytes(sz, 64, slowest->bytes);
        _snwprintf_s(row1, _countof(row1), _TRUNCATE,
                     L"Loading %zu files — %ls%ls",
                     snap.size(), slowest->fileName.c_str(), sz);
        // Row 2: slowest file's live percentages drive the user's perception
        // (matches the bar, which is also driven by the slowest load).
        const wchar_t* phaseTag = L"Loading";
        switch (slowest->phase) {
            case LoadPhase::Reading:   phaseTag = L"Reading";    break;
            case LoadPhase::Rendering: phaseTag = L"Rendering";  break;
            case LoadPhase::Done:      phaseTag = L"Finalizing"; break;
        }
        _snwprintf_s(row2, _countof(row2), _TRUNCATE,
                     L"%ls  ·  read %d%%  ·  render %d%%  ·  +%zu more",
                     phaseTag, slowest->readPct, slowest->renderPct,
                     snap.size() - 1);
    }

    // Re-check HWNDs right before SetWindowTextW — the panel could have
    // been destroyed while we composed the buffers (WM_DESTROY race).
    if (g_hLoadProgressLabel && IsWindow(g_hLoadProgressLabel))
        SetWindowTextW(g_hLoadProgressLabel, row1);
    if (g_hLoadProgressLabel2 && IsWindow(g_hLoadProgressLabel2))
        SetWindowTextW(g_hLoadProgressLabel2, row2);
}

// Helper used by DoFileOpen / WM_DROPFILES / SidebarOpenFile to kick off a
// background load.  All callers funnel through here so the progress UI stays
// in sync.
static void BeginAsyncFileLoadEx(std::unique_ptr<FileLoadPayload> payload) {
    if (!payload || !payload->hMainWnd) return;
    HWND hMainWnd = payload->hMainWnd;
    std::wstring fileName = payload->sFileName;

    // Probe size on the UI thread (cheap stat) so the progress label is correct
    // before the worker starts.  Failure is non-fatal; worker will still report.
    long long sz = 0;
    {
        WIN32_FILE_ATTRIBUTE_DATA fad{};
        if (GetFileAttributesExW(payload->sFilePath.c_str(), GetFileExInfoStandard, &fad)) {
            ULARGE_INTEGER u; u.HighPart = fad.nFileSizeHigh; u.LowPart = fad.nFileSizeLow;
            sz = (long long)u.QuadPart;
        }
    }

    // v4.43: stable LoadId + per-load cancel token allocated BEFORE the
    // worker is spawned.  Both are stored in the payload so the worker
    // and the UI side share one source of truth.
    LoadId loadId = TF_NewLoadId();
    LoadCancelTokenPtr cancelToken = std::make_shared<LoadCancelToken>();
    payload->loadId      = loadId;
    payload->cancelToken = cancelToken;

    // v4.40/v4.43: bind the worker's stable LoadId + cancel token to the
    // already-reserved sidebar tab.  Tab-close uses the token to quarantine
    // the tab while Reading is still in progress; completion/failure uses
    // the LoadId to delete it without falling back to a fresh blank tab.
    if (payload->bFromSidebar) {
        for (auto& up : g_Tabs) {
            EditorTab* t = up.get();   // v4.44: non-owning view
            if (t && t->bAsyncLoading && t->loadId == 0 &&
                _wcsicmp(t->sFilePath.c_str(), payload->sFilePath.c_str()) == 0) {
                t->loadId            = loadId;
                t->cancelToken       = cancelToken;
                payload->targetTabId = t->stableId;   // O2: workers carry ID only
                break;
            }
        }
    }

    // Visual feedback.
    g_ActiveLoads.fetch_add(1);
    {
        // v4.27: count-aware title — keeps per-file context out of the title
        // bar (which would otherwise be overwritten by each new load) and
        // delegates the actual filename / size / percent to the overlay.
        size_t n = (size_t)g_ActiveLoads.load();
        wchar_t titleBuf[160];
        if (n <= 1)
            swprintf(titleBuf, 160,
                     L"| Tiny Fantail | Loading file in background... UI stays responsive.");
        else
            swprintf(titleBuf, 160,
                     L"| Tiny Fantail | Loading %zu files in background... UI stays responsive.", n);
        SetWindowTextW(hMainWnd, titleBuf);
    }
    ShowLoadProgressUI(hMainWnd, fileName, sz, loadId);

    g_ThreadMgr.spawn([p = std::move(payload)]() mutable {
        AsyncFileLoadThreadBody(std::move(p));
    });
}

static void BeginAsyncFileLoad(HWND hMainWnd,
                               const std::wstring& filePath,
                               const std::wstring& workspaceHint = L"") {
    auto payload = std::make_unique<FileLoadPayload>();
    payload->hMainWnd       = hMainWnd;
    payload->sFilePath      = filePath;
    payload->sFileName      = std::filesystem::path(filePath).filename().wstring();
    payload->sWorkspaceHint = workspaceHint;
    BeginAsyncFileLoadEx(std::move(payload));
}


void UpdateEditorFont(HWND hEdit, HWND hGutter, int newSize);
void HandleBlockIndent(HWND hEdit, bool bOutdent, bool bForce = false);
void CaptureBaseline(HWND hEdit);
void RefreshSymbolList(HWND hEdit, HWND hList);
void UpdateColInfo(HWND hEdit);
void UpdatePieceCount(const EditorTab* tab);
void UpdateStatusUI(HWND hStatus, EditorTab* tab);
void DoFileOpen(HWND hwnd);
void RefreshSymbols(HWND hEdit);
void ShowSymbolJumpMenu(HWND hParent);
void PurgeActiveTabRam(HWND hwnd);
void OnEditCompact(HWND hwnd);
static POINT GetCaretScreenPos(HWND hEdit);
// --- File Watcher forward declarations ---
// --- File Watcher forward declarations ---
// Ensure these match the 'static' and return types used in the implementation
static bool FileWatcherStart(HWND hwndOwner, const std::wstring& rootDir);
static void FileWatcherStop();
LRESULT CALLBACK SymbolSearchEditProc(HWND, UINT, WPARAM, LPARAM, UINT_PTR, DWORD_PTR);
// =============================================================================
//  v4.34 — forward declarations for the smooth-typing helpers.
//  The full definitions live further down (next to IDT_EN_CHANGE_COALESCE,
//  which was the v4.32 anchor) but EditSubclassProc — defined ~3000 lines
//  earlier — needs to call them. These forward decls keep the storage
//  class / linkage identical to the definitions below; the One Definition
//  Rule is satisfied because each symbol is defined exactly once.
// =============================================================================
extern const UINT_PTR IDT_EN_CHANGE_COALESCE;
extern const UINT_PTR IDT_STATS_DEFER_COALESCE;
extern const UINT_PTR IDT_GUTTER_LAYOUT_DEFER;
extern const size_t   TF_STATS_FAST_PATH_BYTES;
extern const int      TF_PAINT_MAX_LINE_CHARS;
inline void RequestEditUiRefresh(HWND hMainWnd) noexcept;

// =============================================================================
//  v4.35 — End-user safety helpers (memory / GDI / data integrity).
//  Header-only, zero runtime overhead on the happy path. See banner S1–S6.
// =============================================================================
namespace TF_Safety {

    // S6 — centralised "is this HWND still real" predicate.
    inline bool WindowAlive(HWND h) noexcept {
        return h != nullptr && ::IsWindow(h) != FALSE;
    }

    // S2 — saturating size_t multiply. Used by the v4.34 size-gate so a
    // huge (>SIZE_MAX/sizeof(wchar_t)) doc can never wrap to a small
    // number and bypass the deferred-stats slow path.
    inline size_t MulSatSizeT(size_t a, size_t b) noexcept {
        if (a == 0 || b == 0) return 0;
        if (a > (SIZE_MAX / b)) return SIZE_MAX;
        return a * b;
    }

    // S1 — generic RAII guard for any HGDIOBJ-shaped resource.
    template <typename T>
    struct GdiObjectGuard {
        T h;
        explicit GdiObjectGuard(T h_ = nullptr) noexcept : h(h_) {}
        ~GdiObjectGuard() noexcept { if (h) ::DeleteObject((HGDIOBJ)h); }
        GdiObjectGuard(const GdiObjectGuard&)            = delete;
        GdiObjectGuard& operator=(const GdiObjectGuard&) = delete;
        GdiObjectGuard(GdiObjectGuard&& o) noexcept : h(o.h) { o.h = nullptr; }
        GdiObjectGuard& operator=(GdiObjectGuard&& o) noexcept {
            if (this != &o) { if (h) ::DeleteObject((HGDIOBJ)h); h = o.h; o.h = nullptr; }
            return *this;
        }
        T release() noexcept { T t = h; h = nullptr; return t; }
        T get()     const noexcept { return h; }
        explicit operator bool() const noexcept { return h != nullptr; }
    };

    // S1 — RAII pair for GetDC / ReleaseDC.
    struct ScopedDC {
        HWND wnd;
        HDC  dc;
        ScopedDC(HWND w) noexcept : wnd(w), dc(w ? ::GetDC(w) : nullptr) {}
        ~ScopedDC() noexcept { if (wnd && dc) ::ReleaseDC(wnd, dc); }
        ScopedDC(const ScopedDC&)            = delete;
        ScopedDC& operator=(const ScopedDC&) = delete;
        operator HDC() const noexcept { return dc; }
        bool valid()  const noexcept { return dc != nullptr; }
    };

    // S1 — RAII pair for SelectObject; restores the previous object on scope exit.
    struct ScopedSelectObject {
        HDC      dc;
        HGDIOBJ  prev;
        ScopedSelectObject(HDC d, HGDIOBJ obj) noexcept
            : dc(d), prev(d && obj ? ::SelectObject(d, obj) : nullptr) {}
        ~ScopedSelectObject() noexcept { if (dc && prev) ::SelectObject(dc, prev); }
        ScopedSelectObject(const ScopedSelectObject&)            = delete;
        ScopedSelectObject& operator=(const ScopedSelectObject&) = delete;
    };

} // namespace TF_Safety

LRESULT CALLBACK EditSubclassProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK GutterSubclassProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK TabSubclassProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK JumpMenuContainerSubclass(HWND, UINT, WPARAM, LPARAM, UINT_PTR, DWORD_PTR);

// --- Sidebar (directory tree) forward declarations ---
void SidebarLoadDirectory(HWND hMainWnd, const std::wstring& dirPath,
                          bool forceRefresh = false,
                          const std::wstring& selectAfterLoad = L"",
                          const std::wstring& createChildName = L"",
                          const std::wstring& createParentDir = L"");
void SidebarSyncToActiveTab(HWND hMainWnd, const std::wstring& filePath = L"",
                            bool defineWorkspace = false);
void HandleDirectoryLoaded(HWND hwnd, LPARAM lParam);
unsigned __stdcall DirLoadThreadProc(void* pArg);
void SidebarOpenFile(HWND hMainWnd, const std::wstring& filePath);
void SidebarCreateFolder(HWND hMainWnd);

// --- Splitter / layout persistence ---
void SaveSidebarWidth();
void LoadSidebarWidth();
void ApplySidebarWidth(HWND hMain, int newWidth, bool saveNow = false);
LRESULT CALLBACK SplitterWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

EditorTab* GetActiveTab() {
    // v4.44: non-owning view into the unique_ptr-owned slot.
    if (g_ActiveTabIndex >= 0 && g_ActiveTabIndex < (int)g_Tabs.size())
        return g_Tabs[g_ActiveTabIndex].get();
    return NULL;
}

// =============================================================================
//  RAM TRIM
// =============================================================================
static void TrimProcessRamNow() {
    HeapCompact(GetProcessHeap(), 0);

    typedef BOOL(WINAPI* EmptyWorkingSetProc)(HANDLE);
    HMODULE hPsapi   = GetModuleHandleW(L"psapi.dll");
    bool loadedPsapi = false;
    if (!hPsapi) {
        hPsapi     = LoadLibraryW(L"psapi.dll");
        loadedPsapi = (hPsapi != NULL);
    }
    if (hPsapi) {
        EmptyWorkingSetProc pEWS =
            (EmptyWorkingSetProc)GetProcAddress(hPsapi, "EmptyWorkingSet");
        if (pEWS) pEWS(GetCurrentProcess());
        if (loadedPsapi) FreeLibrary(hPsapi);
    }
    SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
}

// =============================================================================
//  TAB RAM CLEAR
// =============================================================================
static void ClearTabRamPayload(EditorTab* tab, bool clearIdentity, bool clearEditText) {
    if (!tab) return;

    if (tab->hEdit && IsWindow(tab->hEdit)) {
        SendMessage(tab->hEdit, EM_EMPTYUNDOBUFFER, 0, 0);
        if (clearEditText) {
            SendMessage(tab->hEdit, WM_SETREDRAW, FALSE, 0);
            {
                RestoreGuard guard(&tab->isRestoring);
                SetWindowTextW(tab->hEdit, L"");
                SendMessage(tab->hEdit, EM_EMPTYUNDOBUFFER, 0, 0);
            }
            SendMessage(tab->hEdit, WM_SETREDRAW, TRUE, 0);
            InvalidateRect(tab->hEdit, NULL, TRUE);
        }
    }

    std::deque<EditCommand>().swap(tab->undoStack);
    std::deque<EditCommand>().swap(tab->redoStack);
    std::wstring().swap(tab->lastSavedText);
    std::vector<int>().swap(tab->vOriginalIndents);

    // Reset the piece table to empty.
    tab->pt.Clear();
    tab->ptDirty       = false;
    tab->cachedDocDirty = true;
    tab->cachedDoc.clear();

    if (clearIdentity) {
        std::wstring().swap(tab->sFileName);
        std::wstring().swap(tab->sFilePath);
    }

    tab->historyIndex       = 0;
    tab->errorLine          = -1;
    tab->lastScrollV        = 0;
    tab->lastScrollH        = 0;
    tab->initialContentHash = 0;
    tab->lastCommandTime    = std::chrono::steady_clock::now();
}

void PurgeActiveTabRam(HWND hwnd) {
    EditorTab* tab = GetActiveTab();
    if (!tab) return;

    // v4.18 — confirmation prompt for Ctrl+Shift+R.  Purging is destructive:
    // it wipes the in-memory PieceTable, the EDIT control text, undo/redo
    // history and symbol cache for this tab.  Disk content is untouched, but
    // any unsaved edits are lost permanently.  Require an explicit Yes.
    {
        std::wstring prompt = L"Purge RAM for this tab?\n\n";
        if (!tab->sFileName.empty()) {
            prompt += L"File: " + tab->sFileName + L"\n\n";
        }
        prompt += L"This will free the in-memory contents (PieceTable, "
                 L"editor text, undo/redo history).  Unsaved changes will "
                 L"be lost.  The file on disk is not modified, and the tab "
                 L"will reload from disk the next time it is opened.";
        UINT flags = MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2;
        if (tab->bModified) flags |= MB_DEFBUTTON2;  // default to No when dirty
        int answer = MessageBoxW(hwnd, prompt.c_str(),
                                 L"Confirm RAM Purge", flags);
        if (answer != IDYES) {
            SetWindowTextW(hwnd, L"Tiny Fantail | RAM purge cancelled.");
            return;
        }
    }

    HWND hEdit = tab->hEdit;
    // v4.17 fix: previously clearEditText=false, which wiped the PieceTable but
    // left stale text visible in the EDIT control (UI lied about memory state),
    // and left sFilePath set so SidebarOpenFile's duplicate check returned the
    // empty purged tab on reopen.  Now we wipe the EDIT control too AND mark the
    // tab as needing a disk reload, while keeping sFilePath/sFileName so the tab
    // title and identity are preserved.
    ClearTabRamPayload(tab, false, true);
    tab->bPurgedNeedsReload = !tab->sFilePath.empty();
    tab->bModified          = false;

    if (hEdit) {
        globalSymbols.erase(
            std::remove_if(globalSymbols.begin(), globalSymbols.end(),
                [hEdit](const Symbol& s) { return s.hTab == hEdit; }),
            globalSymbols.end());
        g_VisibleSymbols.clear();
    }

    TrimProcessRamNow();

    if (hEdit && IsWindow(hEdit)) {
        UpdateLineCount(hEdit, hGlobalLineCount);
        UpdateWordCount(hEdit, hWordCount);
        UpdateCharacterCount(hEdit, hCharLabel);
        UpdateColInfo(hEdit);
        UpdatePieceCount(tab);
        UpdateGutter(hEdit, tab->hGutter);
        InvalidateRect(hEdit, NULL, TRUE);
        if (tab->hGutter && IsWindow(tab->hGutter))
            InvalidateRect(tab->hGutter, NULL, TRUE);
    }

    SetWindowTextW(hwnd, L"Tiny Fantail | Current tab RAM purged.");
}

// =============================================================================
//  COMMAND HISTORY
// =============================================================================
static std::wstring GetEditTextRange(HWND hEdit, DWORD start, DWORD end) {
    if (!hEdit || end <= start) return L"";

    DWORD textLen = (DWORD)GetWindowTextLength(hEdit);
    start = min(start, textLen);
    end   = min(end,   textLen);
    if (end <= start) return L"";

    std::wstring fullText((size_t)textLen + 1, L'\0');
    GetWindowText(hEdit, &fullText[0], textLen + 1);
    fullText.resize(textLen);
    return fullText.substr(start, end - start);
}

static size_t GetHistoryMemoryCost(const std::deque<EditCommand>& stack) {
    size_t total = 0;
    for (const auto& cmd : stack) total += cmd.memoryCost();
    return total;
}

static void EnforceHistoryBudget(EditorTab* tab) {
    if (!tab) return;

    while (tab->undoStack.size() > MAX_UNDO_LEVELS)
        tab->undoStack.pop_front();
    while (tab->redoStack.size() > MAX_UNDO_LEVELS)
        tab->redoStack.pop_front();

    const size_t maxMemoryLimit = 100 * 1024 * 1024;
    size_t total = GetHistoryMemoryCost(tab->undoStack)
                 + GetHistoryMemoryCost(tab->redoStack);

    while (total > maxMemoryLimit && tab->undoStack.size() > 1) {
        total -= tab->undoStack.front().memoryCost();
        tab->undoStack.pop_front();
    }
    while (total > maxMemoryLimit && !tab->redoStack.empty()) {
        total -= tab->redoStack.front().memoryCost();
        tab->redoStack.pop_front();
    }

    tab->historyIndex = (int)tab->undoStack.size();
}

static EditCommand BeginReplaceCommand(HWND hEdit, DWORD start, DWORD end,
                                       const std::wstring& insertedText,
                                       DWORD caretBeforeStart, DWORD caretBeforeEnd) {
    EditCommand cmd;
    cmd.index            = start;
    cmd.removedText      = GetEditTextRange(hEdit, start, end);
    cmd.insertedText     = insertedText;
    cmd.caretBeforeStart = caretBeforeStart;
    cmd.caretBeforeEnd   = caretBeforeEnd;
    cmd.scrollBeforeV    = (int)SendMessage(hEdit, EM_GETFIRSTVISIBLELINE, 0, 0);
    cmd.scrollBeforeH    = GetScrollPos(hEdit, SB_HORZ);
    return cmd;
}

// Apply a piece-table-aware edit: after committing to the EDIT control, also
// apply the equivalent operation to the piece table so both stay in sync.
// -----------------------------------------------------------------------------
//  ApplyPieceTableEdit — low-level PT mutation.
//
//  CONTRACT (reinforced in v4.25):
//    * tab->pt is the AUTHORITATIVE document model.  The Win32 EDIT control
//      is a VIEW.  This function mutates the model only; the caller is
//      responsible for syncing the view (via the keyboard path's
//      EM_REPLACESEL or the new TF_SyncEditViewFromPT helper below).
//    * Single-threaded: must be called on the UI thread.  PieceTable has
//      no internal locking by design — it is owned exclusively by the UI
//      thread and snapshotted (by value) when handed to worker threads.
//    * Re-entrancy: callers gate via tab->isRestoring (RestoreGuard) or,
//      preferably, via the new MutationGuard inside TF_EditorMutate.
// -----------------------------------------------------------------------------
static void ApplyPieceTableEdit(EditorTab* tab,
                                 size_t pos, size_t removedLen,
                                 const std::wstring& inserted) {
    if (!tab) return;
    TF_AssertUIThread();   // v4.26: PT/undo are UI-thread-only
    if (removedLen > 0) tab->pt.Delete(pos, removedLen);
    if (!inserted.empty()) tab->pt.Insert(pos, inserted);
    tab->ptDirty       = false;
    tab->cachedDocDirty = true;
    // v4.26: bump the auto-compaction edit counter.  Saturating add — even
    // pathological scripted callers cannot wrap the counter back to zero
    // and bypass the threshold.
    if (tab->editsSinceCompact < (size_t)-2) ++tab->editsSinceCompact;
}

// =============================================================================
//  v4.25 — MUTATION PIPELINE
//
//  Single canonical funnel for every NEW state-changing edit.  Existing
//  keyboard-path call sites (CommitEditCommand) are unchanged because they
//  already own the undo-stack invariants and operate in a known-safe context.
//  Any other mutation — paste handlers, refactor tools, scripted transforms,
//  future AI-driven edits — should go through TF_EditorMutate so that:
//
//      * Stale tab pointers cannot crash the editor.
//      * Out-of-range pos/len cannot corrupt the PT (clamped, never throws).
//      * Nested mutation attempts (e.g. an EN_CHANGE re-entry) are rejected
//        instead of doubling the undo entry.
//      * The EDIT control is updated AFTER the model, never before — so the
//        on-screen state can never out-run the source of truth.
// =============================================================================

// Tab-level liveness check: tab pointer non-null AND its EDIT view alive.
static inline bool TF_TabIsAlive(const EditorTab* tab) noexcept {
    return tab != nullptr && TF_SafeIsAlive(tab->hEdit);
}

// Clamps [pos, pos+len] to [0, docLen].  Returns the (possibly shrunk) span.
// All-zero-length spans are valid and represent a pure-insertion at pos.
static inline void TF_NormalizeRange(size_t& pos, size_t& removedLen,
                                     size_t docLen) noexcept {
    if (pos > docLen) pos = docLen;
    size_t maxRemove = docLen - pos;
    if (removedLen > maxRemove) removedLen = maxRemove;
}

// RAII re-entrancy lock.  Built on the existing EditorTab::isRestoring flag
// so it composes cleanly with RestoreGuard (the keyboard path's own gate).
// If isRestoring is already set, acquired() returns false and the caller
// must abort — the mutation is being attempted reentrantly from within
// another mutation (typically an EN_CHANGE handler).
class MutationGuard {
    EditorTab* m_tab;
    bool       m_acquired;
public:
    explicit MutationGuard(EditorTab* tab) noexcept
        : m_tab(tab), m_acquired(false) {
        if (m_tab && !m_tab->isRestoring) {
            m_tab->isRestoring = true;
            m_acquired = true;
        }
    }
    ~MutationGuard() noexcept {
        if (m_acquired && m_tab) m_tab->isRestoring = false;
    }
    bool acquired() const noexcept { return m_acquired; }
    MutationGuard(const MutationGuard&)            = delete;
    MutationGuard& operator=(const MutationGuard&) = delete;
};

// PT -> EDIT view sync for the visible window.  Marks the cached-doc span
// dirty (the WM_PAINT handler will refill it from pt.GetVirtualSpan on next
// paint) and requests a guarded repaint via the v4.24 safety layer.  Does
// NOT call EM_SETTEXT — bulk text replacement is handled by BulkSetEditText
// on its own dedicated path.
static inline void TF_SyncEditViewFromPT(EditorTab* tab) noexcept {
    if (!TF_TabIsAlive(tab)) return;
    tab->cachedDocDirty = true;
    TF_SafeInvalidate(tab->hEdit, nullptr, FALSE);
    if (TF_SafeIsAlive(tab->hGutter)) {
        TF_SafeInvalidate(tab->hGutter, nullptr, FALSE);
    }
}

// THE canonical mutation entry point.  Returns true iff the edit was applied.
// Failure modes (all return false, never throw, never block):
//    * tab is null or its EDIT view has been destroyed.
//    * Another mutation is already in progress on this tab (re-entrancy).
//    * The normalised range is empty AND inserted is empty (no-op).
static inline void TF_MaybeAutoCompactPT(EditorTab* tab) noexcept;  // v4.26 fwd
static inline bool TF_EditorMutate(EditorTab* tab,
                                   size_t pos, size_t removedLen,
                                   const std::wstring& inserted) noexcept {
    if (!TF_TabIsAlive(tab)) return false;

    MutationGuard lock(tab);
    if (!lock.acquired()) return false;        // re-entrancy: refuse silently

    TF_NormalizeRange(pos, removedLen, tab->pt.Length());
    if (removedLen == 0 && inserted.empty()) return false;

    ApplyPieceTableEdit(tab, pos, removedLen, inserted);

    tab->bModified      = true;
    tab->cachedDocDirty = true;

    // View follows model — never the other way around for this path.
    TF_SyncEditViewFromPT(tab);

    // v4.26: opportunistic auto-compaction (defined just below).  Cheap
    // counter check first; the actual compact only runs at thresholds.
    TF_MaybeAutoCompactPT(tab);
    return true;
}

// =============================================================================
//  v4.26 — PIECE TABLE AUTO-COMPACTION
//
//  After hours of editing the splay tree accumulates many small pieces.
//  Splay lookups stay O(log N), but two costs grow with fragmentation:
//    (a) GetVirtualText() flatten on save / search / AI handoff.
//    (b) Working-set footprint of the add-buffer arenas.
//
//  TF_MaybeAutoCompactPT is called from CommitEditCommand and TF_EditorMutate
//  and decides — with cheap counter / size checks first, then a single
//  pt.GetPieceCount() probe — whether to invoke pt.Compact().
//
//  Compaction is SAFE because:
//    * pt.Compact() only rewrites the buffer; the undo / redo command lists
//      live on EditorTab and are completely untouched.  Caret/scroll are
//      preserved by the EDIT control's own state (we don't touch hEdit here).
//    * MutationGuard prevents re-entrancy: a Compact()-induced cache
//      invalidation that fires another mutation would be rejected silently.
//    * The compactor is gated on tab->isRestoring being false, so an active
//      undo/redo cycle is never interrupted mid-operation.
//
//  Tunables:
//    TF_AUTO_COMPACT_EDITS  — every N edits, force a compaction probe.
//    TF_AUTO_COMPACT_PIECES — absolute piece-count ceiling.
//    TF_AUTO_COMPACT_GROWTH — multiplicative growth factor over the last
//                              compacted piece count.
// =============================================================================
static constexpr size_t TF_AUTO_COMPACT_EDITS  = 4096;
static constexpr size_t TF_AUTO_COMPACT_PIECES = 8192;
static constexpr size_t TF_AUTO_COMPACT_GROWTH = 4;     // 4x lastCompactNodeCount
static constexpr size_t TF_AUTO_COMPACT_MIN_NODES = 64; // skip tiny docs

static inline void TF_MaybeAutoCompactPT(EditorTab* tab) noexcept {
    if (!tab) return;
    if (tab->isRestoring) return;             // never during undo/redo

    // Cheapest gate first: edit count below threshold AND nothing else
    // suggests fragmentation? Skip without ever asking the PT.
    if (tab->editsSinceCompact < TF_AUTO_COMPACT_EDITS) {
        // Still cheap: a single PT method call.
        size_t nodes = tab->pt.GetPieceCount();
        if (nodes < TF_AUTO_COMPACT_PIECES &&
            (tab->lastCompactNodeCount == 0 ||
             nodes < TF_AUTO_COMPACT_GROWTH * tab->lastCompactNodeCount)) {
            return;
        }
        if (nodes < TF_AUTO_COMPACT_MIN_NODES) return;
    }

    // Re-entrancy guard: if another mutation owns the tab right now, defer
    // compaction to the next call.  Compact() itself is single-threaded.
    MutationGuard lock(tab);
    if (!lock.acquired()) return;

    try {
        tab->pt.Compact();
    } catch (...) {
        // Compaction is best-effort.  A failure (e.g. transient OOM during
        // the temporary copy) leaves the PT in its previous valid state.
        return;
    }

    tab->editsSinceCompact    = 0;
    tab->lastCompactNodeCount = tab->pt.GetPieceCount();
    tab->cachedDocDirty       = true;
    // No view sync needed: Compact() preserves the virtual text byte-for-byte;
    // the EDIT control already shows the correct characters.
}


static void CommitEditCommand(EditorTab* tab, EditCommand& cmd, bool allowCoalesce) {
    if (!tab || tab->isRestoring) return;
    if (cmd.removedText.empty() && cmd.insertedText.empty()) return;
    TF_AssertUIThread();   // v4.26: undo stack + PT are UI-thread-only

    DWORD afterStart = 0, afterEnd = 0;
    SendMessage(tab->hEdit, EM_GETSEL, (WPARAM)&afterStart, (LPARAM)&afterEnd);
    cmd.caretAfterStart = afterStart;
    cmd.caretAfterEnd   = afterEnd;
    cmd.scrollAfterV    = (int)SendMessage(tab->hEdit, EM_GETFIRSTVISIBLELINE, 0, 0);
    cmd.scrollAfterH    = GetScrollPos(tab->hEdit, SB_HORZ);
    cmd.tick            = GetTickCount();

    // Sync the piece table with the edit that just happened.
    ApplyPieceTableEdit(tab, cmd.index,
                        cmd.removedText.size(),
                        cmd.insertedText);

    if (!tab->redoStack.empty()) {
        tab->redoStack.clear();
        tab->redoStack.shrink_to_fit();
    }

    bool merged = false;
    if (allowCoalesce && cmd.isInsertOnly() && !tab->undoStack.empty()) {
        EditCommand& prev  = tab->undoStack.back();
        DWORD elapsed      = cmd.tick - prev.tick;
        DWORD prevEnd      = prev.index + (DWORD)prev.insertedText.length();
        if (prev.isInsertOnly() && elapsed <= UNDO_COALESCE_MS
                && prevEnd == cmd.index
                && prev.caretAfterStart == cmd.caretBeforeStart
                && prev.caretAfterEnd   == cmd.caretBeforeEnd) {
            prev.insertedText    += cmd.insertedText;
            prev.caretAfterStart  = cmd.caretAfterStart;
            prev.caretAfterEnd    = cmd.caretAfterEnd;
            prev.scrollAfterV     = cmd.scrollAfterV;
            prev.scrollAfterH     = cmd.scrollAfterH;
            prev.tick             = cmd.tick;
            merged = true;
        }
    }

    if (!merged) tab->undoStack.push_back(std::move(cmd));

    tab->bModified        = true;
    tab->cachedDocDirty   = true;
    tab->lastCommandTime  = std::chrono::steady_clock::now();
    EnforceHistoryBudget(tab);

    // v4.26: opportunistic compaction at the bottom of the keyboard path.
    // Cheap counter check; only invokes Compact() at thresholds.
    TF_MaybeAutoCompactPT(tab);
}

static void ReplaceSelectionWithHistory(HWND hEdit, EditorTab* tab,
                                        const std::wstring& insertedText,
                                        bool allowCoalesce = false) {
    if (!hEdit) return;
    if (!tab || tab->isRestoring) {
        SendMessage(hEdit, EM_REPLACESEL, TRUE, (LPARAM)insertedText.c_str());
        return;
    }

    DWORD start = 0, end = 0;
    SendMessage(hEdit, EM_GETSEL, (WPARAM)&start, (LPARAM)&end);
    EditCommand cmd = BeginReplaceCommand(hEdit, start, end, insertedText, start, end);
    SendMessage(hEdit, EM_REPLACESEL, TRUE, (LPARAM)insertedText.c_str());
    CommitEditCommand(tab, cmd, allowCoalesce);
}

static void RestoreEditScroll(HWND hEdit, int targetV, int targetH) {
    int currentV = (int)SendMessage(hEdit, EM_GETFIRSTVISIBLELINE, 0, 0);
    int currentH = GetScrollPos(hEdit, SB_HORZ);
    SendMessage(hEdit, EM_LINESCROLL, targetH - currentH, targetV - currentV);
}

static void ApplyEditCommand(HWND hEdit, EditorTab* tab,
                              const EditCommand& cmd, bool undo) {
    if (!hEdit || !tab) return;

    SendMessage(hEdit, WM_SETREDRAW, FALSE, 0);
    {
        RestoreGuard guard(&tab->isRestoring);
        DWORD replaceStart = cmd.index;
        DWORD replaceEnd   = cmd.index +
            (DWORD)(undo ? cmd.insertedText.length() : cmd.removedText.length());
        DWORD textLen  = (DWORD)GetWindowTextLength(hEdit);
        replaceStart   = min(replaceStart, textLen);
        replaceEnd     = min(replaceEnd,   textLen);
        const std::wstring& replacement = undo ? cmd.removedText : cmd.insertedText;

        SendMessage(hEdit, EM_SETSEL,     replaceStart, replaceEnd);
        SendMessage(hEdit, EM_REPLACESEL, FALSE, (LPARAM)replacement.c_str());
        SendMessage(hEdit, EM_EMPTYUNDOBUFFER, 0, 0);

        if (undo) {
            SendMessage(hEdit, EM_SETSEL, cmd.caretBeforeStart, cmd.caretBeforeEnd);
            RestoreEditScroll(hEdit, cmd.scrollBeforeV, cmd.scrollBeforeH);
        } else {
            SendMessage(hEdit, EM_SETSEL, cmd.caretAfterStart, cmd.caretAfterEnd);
            RestoreEditScroll(hEdit, cmd.scrollAfterV, cmd.scrollAfterH);
        }
    }
    SendMessage(hEdit, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(hEdit, NULL, TRUE);

    // After undo/redo the EDIT control content changed; resync the piece table.
    tab->SyncPieceTableFromEdit();

    tab->bModified      = true;
    tab->cachedDocDirty = true;
}

static bool UndoEditCommand(EditorTab* tab) {
    if (!tab || !tab->hEdit || tab->undoStack.empty()) return false;

    EditCommand cmd = std::move(tab->undoStack.back());
    tab->undoStack.pop_back();
    ApplyEditCommand(tab->hEdit, tab, cmd, true);
    tab->redoStack.push_back(std::move(cmd));
    EnforceHistoryBudget(tab);
    return true;
}

static bool RedoEditCommand(EditorTab* tab) {
    if (!tab || !tab->hEdit || tab->redoStack.empty()) return false;

    EditCommand cmd = std::move(tab->redoStack.back());
    tab->redoStack.pop_back();
    ApplyEditCommand(tab->hEdit, tab, cmd, false);
    tab->undoStack.push_back(std::move(cmd));
    EnforceHistoryBudget(tab);
    return true;
}

void UpdateStatusUI(HWND hStatus, EditorTab* tab) {
    if (!tab) return;
    wchar_t statBuf[256];
    // v4.41a: surface the GDI handle counter alongside undo/redo depth so
    // a long editing session can spot a leaking code path before it
    // exhausts the per-process GDI quota (default 10 000).
    const int gdi = tf_v441::Reliability::GdiGet();
    swprintf(statBuf, 256, L"History: %d | %zu | GDI: %d",
             tab->historyIndex,
             tab->redoStack.size(),
             gdi);
    SendMessage(hStatus, SB_SETTEXT, 2, (LPARAM)statBuf);
}

// =============================================================================
//  JUMP MENU SUBCLASSES
// =============================================================================
LRESULT CALLBACK JumpMenuContainerSubclass(HWND hWnd, UINT uMsg,
                                            WPARAM wParam, LPARAM lParam,
                                            UINT_PTR uIdSubclass, DWORD_PTR) {
    switch (uMsg) {
        case WM_CTLCOLORLISTBOX: {
            HBRUSH hListBoxBrush = (HBRUSH)GetProp(hWnd, L"MY_BACK_BRUSH");
            if (!hListBoxBrush) {
                hListBoxBrush = CreateSolidBrush(RGB(35, 35, 35));
                SetProp(hWnd, L"MY_BACK_BRUSH", (HANDLE)hListBoxBrush);
            }
            SetBkColor((HDC)wParam, RGB(35, 35, 35));
            return (LRESULT)hListBoxBrush;
        }
        case WM_ERASEBKGND: {
            RECT rc;
            GetClientRect(hWnd, &rc);
            HBRUSH hBrush = (HBRUSH)GetProp(hWnd, L"MY_BACK_BRUSH");
            if (hBrush) {
                FillRect((HDC)wParam, &rc, hBrush);
            } else {
                ScopedGdiObject tb(CreateSolidBrush(RGB(35, 35, 35)));
                if (tb.isValid()) FillRect((HDC)wParam, &rc, (HBRUSH)tb.get());
            }
            return 1;
        }
        case WM_MEASUREITEM: {
            LPMEASUREITEMSTRUCT lpmis = (LPMEASUREITEMSTRUCT)lParam;
            if (lpmis->CtlID == IDC_SYMBOL_LIST) {
                lpmis->itemHeight = ScaleForDpi(28, GetDpiForHwnd(hWnd));
                return TRUE;
            }
            break;
        }
        case WM_DRAWITEM: {
            LPDRAWITEMSTRUCT lpdis = (LPDRAWITEMSTRUCT)lParam;
            if (lpdis->itemID == (UINT)-1) return TRUE;

            bool isSelected = (lpdis->itemState & ODS_SELECTED) != 0;
            {
                ScopedGdiObject hBrush(CreateSolidBrush(isSelected ? RGB(220,20,60) : RGB(35,35,35)));
                if (hBrush.isValid())
                    FillRect(lpdis->hDC, &lpdis->rcItem, (HBRUSH)hBrush.get());
            }

            int itemLen = (int)SendMessage(lpdis->hwndItem, LB_GETTEXTLEN, lpdis->itemID, 0);
            std::vector<wchar_t> textBuf(itemLen + 1, L'\0');
            SendMessage(lpdis->hwndItem, LB_GETTEXT, lpdis->itemID, (LPARAM)textBuf.data());

            SetBkMode(lpdis->hDC, TRANSPARENT);
            SetTextColor(lpdis->hDC, isSelected ? RGB(255,255,255) : RGB(220,220,220));

            RECT rcT  = lpdis->rcItem;
            rcT.left += 10;
            HFONT hFont = (HFONT)SendMessage(lpdis->hwndItem, WM_GETFONT, 0, 0);
            HFONT hOld  = hFont ? (HFONT)SelectObject(lpdis->hDC, hFont) : NULL;
            DrawText(lpdis->hDC, textBuf.data(), -1, &rcT,
                     DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);
            if (hOld) SelectObject(lpdis->hDC, hOld);
            if ((lpdis->itemState & ODS_FOCUS) && GetFocus() == lpdis->hwndItem)
                DrawFocusRect(lpdis->hDC, &lpdis->rcItem);
            return TRUE;
        }
        case WM_NCDESTROY: {
            HBRUSH hB = (HBRUSH)GetProp(hWnd, L"MY_BACK_BRUSH");
            if (hB) DeleteObject(hB);
            RemoveProp(hWnd, L"MY_BACK_BRUSH");
            HFONT hF = (HFONT)GetProp(hWnd, L"MY_FONT");
            if (hF) DeleteObject(hF);
            RemoveProp(hWnd, L"MY_FONT");
            RemoveWindowSubclass(hWnd, JumpMenuContainerSubclass, uIdSubclass);
            break;
        }
    }
    return DefSubclassProc(hWnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK SymbolSearchEditProc(HWND hWnd, UINT uMsg,
                                       WPARAM wParam, LPARAM lParam,
                                       UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    HWND hList = (HWND)dwRefData;
    switch (uMsg) {
        case WM_KEYDOWN:
            if (wParam == VK_DOWN) {
                if (SendMessage(hList, LB_GETCOUNT, 0, 0) > 0) {
                    SetFocus(hList);
                    if (SendMessage(hList, LB_GETCURSEL, 0, 0) == LB_ERR)
                        SendMessage(hList, LB_SETCURSEL, 0, 0);
                }
                return 0;
            }
            if (wParam == VK_ESCAPE) {
                ReleaseCapture();
                if (g_hJumpMenuWnd) { DestroyWindow(g_hJumpMenuWnd); g_hJumpMenuWnd = NULL; }
                return 0;
            }
            if (wParam == VK_RETURN) {
                if (SendMessage(hList, LB_GETCOUNT, 0, 0) > 0) {
                    if (SendMessage(hList, LB_GETCURSEL, 0, 0) == LB_ERR)
                        SendMessage(hList, LB_SETCURSEL, 0, 0);
                    SendMessage(GetParent(hWnd), WM_COMMAND,
                                MAKEWPARAM(IDC_SYMBOL_LIST, LBN_DBLCLK), (LPARAM)hList);
                }
                return 0;
            }
            break;
        case WM_CHAR: {
            LRESULT res = DefSubclassProc(hWnd, uMsg, wParam, lParam);
            RefreshSymbolList(hWnd, hList);
            if (SendMessage(hList, LB_GETCOUNT, 0, 0) >= 1)
                SendMessage(hList, LB_SETCURSEL, 0, 0);
            return res;
        }
    }
    return DefSubclassProc(hWnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK SymbolListSubclassProc(HWND hWnd, UINT uMsg,
                                         WPARAM wParam, LPARAM lParam,
                                         UINT_PTR uIdSubclass, DWORD_PTR) {
    switch (uMsg) {
        case WM_LBUTTONDOWN: {
            if (!g_hJumpMenuWnd || !IsWindow(g_hJumpMenuWnd)) return 0;
            RECT rect; GetWindowRect(g_hJumpMenuWnd, &rect);
            POINT pt;  GetCursorPos(&pt);
            if (!PtInRect(&rect, pt)) {
                ReleaseCapture();
                DestroyWindow(g_hJumpMenuWnd);
                g_hJumpMenuWnd = NULL;
                return 0;
            }
            ReleaseCapture();
            SendMessage(g_hJumpMenuWnd, WM_NCLBUTTONDOWN, HTCAPTION, 0);
            return 0;
        }
        case WM_CHAR: {
            if (wParam >= 32 || wParam == VK_BACK) {
                if (!g_hJumpMenuWnd || !IsWindow(g_hJumpMenuWnd)) return 0;
                HWND hSearch = GetDlgItem(g_hJumpMenuWnd, IDC_SYMBOL_SEARCH);
                if (!hSearch || !IsWindow(hSearch)) return 0;
                SetFocus(hSearch);
                SendMessage(hSearch, WM_CHAR, wParam, lParam);
                int len = GetWindowTextLength(hSearch);
                SendMessage(hSearch, EM_SETSEL, len, len);
                return 0;
            }
            break;
        }
        case WM_KEYDOWN:
            if (wParam == VK_UP) {
                if (SendMessage(hWnd, LB_GETCURSEL, 0, 0) == 0) {
                    if (!g_hJumpMenuWnd || !IsWindow(g_hJumpMenuWnd)) return 0;
                    HWND hSearch = GetDlgItem(g_hJumpMenuWnd, IDC_SYMBOL_SEARCH);
                    if (hSearch && IsWindow(hSearch)) SetFocus(hSearch);
                    return 0;
                }
            }
            if (wParam == VK_RETURN) {
                int sel = (int)SendMessage(hWnd, LB_GETCURSEL, 0, 0);
                if (sel != LB_ERR && (size_t)sel < g_VisibleSymbols.size()) {
                    const Symbol* pSym = g_VisibleSymbols[sel];
                    if (!pSym || !pSym->hTab || !IsWindow(pSym->hTab)) return 0;
                    HWND hEdit = pSym->hTab;

                    RECT rcEdit; GetClientRect(hEdit, &rcEdit);
                    {
                        ScopedDC hdc(hEdit);
                        if (hdc.isValid()) {
                            TEXTMETRIC tm;
                            ScopedSelectObject selFont(hdc,
                                (HFONT)SendMessage(hEdit, WM_GETFONT, 0, 0));
                            GetTextMetrics(hdc, &tm);
                            int lineH      = tm.tmHeight;
                            int visLines   = (rcEdit.bottom - rcEdit.top) /
                                             (lineH > 0 ? lineH : 1);
                            int targetLine = pSym->line - 1;
                            int firstVis   = (int)SendMessage(hEdit, EM_GETFIRSTVISIBLELINE, 0, 0);
                            SendMessage(hEdit, EM_LINESCROLL, 0,
                                        targetLine - firstVis - (visLines / 2));
                        }
                    }

                    LRESULT charIdx = SendMessage(hEdit, EM_LINEINDEX, pSym->line - 1, 0);
                    SendMessage(hEdit, EM_SETSEL, charIdx, charIdx);
                    SetProp(hEdit, L"HighlightLine",  (HANDLE)(DWORD_PTR)(pSym->line - 1));
                    SetProp(hEdit, L"HighlightTimer", (HANDLE)12);
                    SetTimer(hEdit, 999, 3000, NULL);
                    SetFocus(hEdit);
                    InvalidateRect(hEdit, NULL, FALSE);
                }
                ReleaseCapture();
                if (g_hJumpMenuWnd && IsWindow(g_hJumpMenuWnd))
                    DestroyWindow(g_hJumpMenuWnd);
                g_hJumpMenuWnd = NULL;
                return 0;
            }
            if (wParam == VK_ESCAPE) {
                ReleaseCapture();
                if (g_hJumpMenuWnd && IsWindow(g_hJumpMenuWnd))
                    DestroyWindow(g_hJumpMenuWnd);
                g_hJumpMenuWnd = NULL;
                return 0;
            }
            break;
        case WM_KILLFOCUS: {
            HWND hNewFocus = (HWND)wParam;
            HWND hSearch   = (g_hJumpMenuWnd && IsWindow(g_hJumpMenuWnd))
                             ? GetDlgItem(g_hJumpMenuWnd, IDC_SYMBOL_SEARCH)
                             : NULL;
            if (g_hJumpMenuWnd && IsWindow(g_hJumpMenuWnd) &&
                hNewFocus != hSearch &&
                hNewFocus != hWnd   &&
                hNewFocus != g_hJumpMenuWnd) {
                ReleaseCapture();
                DestroyWindow(g_hJumpMenuWnd);
                g_hJumpMenuWnd = NULL;
            }
            return 0;
        }
        case WM_NCDESTROY:
            RemoveWindowSubclass(hWnd, SymbolListSubclassProc, uIdSubclass);
            break;
    }
    return DefSubclassProc(hWnd, uMsg, wParam, lParam);
}

void RefreshSymbolList(HWND hEdit, HWND hList) {
    wchar_t filter[128];
    GetWindowText(hEdit, filter, 128);

    std::wstring query = filter;
    for (auto& c : query) c = towlower(c);

    SendMessage(hList, WM_SETREDRAW, FALSE, 0);
    SendMessage(hList, LB_RESETCONTENT, 0, 0);
    g_VisibleSymbols.clear();

    for (const auto& sym : globalSymbols) {
        std::wstring nameLower = sym.name;
        for (auto& c : nameLower) c = towlower(c);

        if (query.empty() || nameLower.find(query) != std::wstring::npos) {
            g_VisibleSymbols.push_back(&sym);
            std::wstring display = L"  " + sym.name +
                                   L"  [Line " + std::to_wstring(sym.line) + L"]";
            SendMessage(hList, LB_ADDSTRING, 0, (LPARAM)display.c_str());
        }
    }

    SendMessage(hList, LB_SETCURSEL, 0, 0);
    SendMessage(hList, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(hList, NULL, TRUE);
}

// Symbol indexing: reads from the Piece Table's virtual text for the active tab
// (no additional GetWindowText call needed) to keep it O(pieces) instead of
// always O(n).  Falls back to GetWindowText for non-active-tab windows.
void RefreshSymbols(HWND hEdit) {
    HWND hMain = GetAncestor(hEdit, GA_ROOT);

    globalSymbols.erase(
        std::remove_if(globalSymbols.begin(), globalSymbols.end(),
            [hEdit](const Symbol& s) { return s.hTab == hEdit; }),
        globalSymbols.end());

    // Find the EditorTab associated with this HWND.
    EditorTab* ownerTab = nullptr;
    for (auto& up : g_Tabs) {
        EditorTab* t = up.get();
        if (t && t->hEdit == hEdit) { ownerTab = t; break; }
    }

    // Get the document text — prefer the piece table if available.
    std::wstring content;
    if (ownerTab) {
        content = ownerTab->GetDocument();
    } else {
        int len = GetWindowTextLength(hEdit);
        if (len == 0) {
            SetWindowText(hMain, L"Tiny Fantail | Editor Empty");
            return;
        }
        std::vector<wchar_t> buf(len + 1);
        GetWindowText(hEdit, buf.data(), len + 1);
        content.assign(buf.data(), (size_t)len);
    }

    if (content.empty()) {
        SetWindowText(hMain, L"Tiny Fantail | Editor Empty");
        return;
    }

    SetWindowText(hMain, L"Tiny Fantail | Scanning File...");
    UpdateWindow(hMain);

    std::vector<std::wstring> patterns = {
        L"void ", L"class ", L"struct ", L"def ", L"case ",
        L"global ", L"nonlocal ", L"LRESULT ", L"CALLBACK "
    };

    for (const auto& p : patterns) {
        size_t pos = content.find(p, 0);
        while (pos != std::wstring::npos) {
            size_t lineStart = content.find_last_of(L"\n", pos);
            lineStart        = (lineStart == std::wstring::npos) ? 0 : lineStart + 1;
            std::wstring leadingText = content.substr(lineStart, pos - lineStart);

            if (leadingText.find(L"//") == std::wstring::npos &&
                leadingText.find(L"#")  == std::wstring::npos &&
                (pos == 0 || iswspace(content[pos - 1]))) {

                size_t nameStart = pos + p.length();
                size_t nameEnd   = content.find_first_of(L" (:\r\n{", nameStart);

                if (nameEnd != std::wstring::npos && nameEnd > nameStart) {
                    std::wstring name = content.substr(nameStart, nameEnd - nameStart);
                    int line = (int)SendMessage(hEdit, EM_LINEFROMCHAR,
                                               (WPARAM)pos, 0) + 1;
                    globalSymbols.push_back({ name, line, hEdit });
                }
            }
            pos = content.find(p, pos + 1);
        }
    }

    wchar_t status[150];
    swprintf(status, 150,
             L"Tiny Fantail | Indexed %zu Elements. Press F7 to Jump.",
             globalSymbols.size());
    SetWindowText(hMain, status);
}

void ShowSymbolJumpMenu(HWND hParent) {
    if (g_hJumpMenuWnd && IsWindow(g_hJumpMenuWnd)) {
        ReleaseCapture();
        DestroyWindow(g_hJumpMenuWnd);
        g_hJumpMenuWnd = NULL;
    }

    if (globalSymbols.empty()) {
        MessageBox(hParent,
                   L"No Elements indexed. Press F7 after typing code!",
                   L"No Elements to Jump!", MB_OK | MB_ICONINFORMATION);
        return;
    }

    std::sort(globalSymbols.begin(), globalSymbols.end(),
              [](const Symbol& a, const Symbol& b) { return a.name < b.name; });

    int  dpiY  = GetDpiForHwnd(hParent);
    auto Scale = [dpiY](int val) { return MulDiv(val, dpiY, 96); };

    POINT pt; GetCursorPos(&pt);
    HINSTANCE hInst = GetModuleHandle(NULL);

    int width      = Scale(300);
    int rowHeight  = Scale(28);
    int maxVisible = 7;
    int count      = (int)globalSymbols.size();
    int visCount   = (count > maxVisible) ? maxVisible : count;
    int totalHeight = (visCount * rowHeight) + Scale(36);

    HMONITOR hMon = MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST);
    MONITORINFO mi = { sizeof(mi) };
    GetMonitorInfo(hMon, &mi);
    if (pt.x + width       > mi.rcWork.right)  pt.x = mi.rcWork.right  - width       - 5;
    if (pt.y + totalHeight > mi.rcWork.bottom)  pt.y = mi.rcWork.bottom - totalHeight - 5;
    if (pt.x < mi.rcWork.left)  pt.x = mi.rcWork.left;
    if (pt.y < mi.rcWork.top)   pt.y = mi.rcWork.top;

    g_hJumpMenuWnd = CreateWindowEx(
        WS_EX_TOOLWINDOW | WS_EX_TOPMOST,
        L"Static", NULL, WS_POPUP | WS_BORDER,
        pt.x, pt.y, width, totalHeight,
        hParent, NULL, hInst, NULL);
    if (!g_hJumpMenuWnd) return;

    SetWindowSubclass(g_hJumpMenuWnd, JumpMenuContainerSubclass, 0, 0);

    HWND hSearch = CreateWindowEx(
        0, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        Scale(2), Scale(2), width - Scale(4), rowHeight,
        g_hJumpMenuWnd, (HMENU)IDC_SYMBOL_SEARCH, hInst, NULL);
    SendMessage(hSearch, EM_SETMARGINS, EC_LEFTMARGIN, MAKELONG(Scale(8), 0));

    HWND hList = CreateWindowEx(
        0, L"LISTBOX", NULL,
        WS_CHILD | WS_VISIBLE | WS_VSCROLL |
        LBS_NOTIFY | LBS_HASSTRINGS | LBS_WANTKEYBOARDINPUT | LBS_OWNERDRAWFIXED,
        0, rowHeight + Scale(4), width, totalHeight - (rowHeight + Scale(4)),
        g_hJumpMenuWnd, (HMENU)IDC_SYMBOL_LIST, hInst, NULL);

    HFONT hFont = CreateFont(Scale(18), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                              CLEARTYPE_QUALITY, VARIABLE_PITCH | FF_SWISS, L"Segoe UI");
    SetProp(g_hJumpMenuWnd, L"MY_FONT", (HANDLE)hFont);
    SendMessage(hSearch, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hList,   WM_SETFONT, (WPARAM)hFont, TRUE);

    SetWindowSubclass(hSearch, SymbolSearchEditProc,   0, (DWORD_PTR)hList);
    SetWindowSubclass(hList,   SymbolListSubclassProc, 0, 0);

    RefreshSymbolList(hSearch, hList);
    ShowWindow(g_hJumpMenuWnd, SW_SHOW);
    SetFocus(hSearch);
    SetCapture(g_hJumpMenuWnd);
}

// =============================================================================
//  INDENT BASELINE CAPTURE
// =============================================================================
void CaptureBaseline(HWND hEdit) {
    EditorTab* tab = nullptr;
    if (hEdit && IsWindow(hEdit)) {
        tab = reinterpret_cast<EditorTab*>(GetWindowLongPtr(hEdit, GWLP_USERDATA));
    }
    if (!tab) tab = GetActiveTab();
    if (!tab) return;

    const std::wstring& doc = tab->GetDocument();

    tab->vOriginalIndents.clear();
    tab->vOriginalIndents.reserve(1 + (size_t)std::count(doc.begin(), doc.end(), L'\n'));

    if (doc.empty()) {
        tab->vOriginalIndents.push_back(0);
        return;
    }

    int lead = 0;
    bool measuringIndent = true;

    for (wchar_t c : doc) {
        if (c == L'\r') continue;

        if (c == L'\n') {
            tab->vOriginalIndents.push_back(lead);
            lead = 0;
            measuringIndent = true;
            continue;
        }

        if (measuringIndent) {
            if (c == L' ' || c == L'\t') {
                ++lead;
            } else {
                measuringIndent = false;
            }
        }
    }

    tab->vOriginalIndents.push_back(lead);
}

// =============================================================================
//  BLOCK INDENT / OUTDENT
// =============================================================================
void HandleBlockIndent(HWND hEdit, bool bOutdent, bool bForce) {
    int firstVisible = (int)SendMessage(hEdit, EM_GETFIRSTVISIBLELINE, 0, 0);
    DWORD start, end;
    SendMessage(hEdit, EM_GETSEL, (WPARAM)&start, (LPARAM)&end);

    int startLine = (int)SendMessage(hEdit, EM_LINEFROMCHAR, start, 0);
    int endLine   = (int)SendMessage(hEdit, EM_LINEFROMCHAR, end,   0);

    if (start != end && endLine > startLine)
        if ((int)SendMessage(hEdit, EM_LINEINDEX, endLine, 0) == (int)end)
            endLine--;

    EditorTab* tab           = GetActiveTab();
    bool       bUserAllowForce = bForce;

    if (bOutdent && !bUserAllowForce && tab) {
        for (int i = startLine; i <= endLine; i++) {
            int lineIndex = (int)SendMessage(hEdit, EM_LINEINDEX, i, 0);
            int lineLen   = (int)SendMessage(hEdit, EM_LINELENGTH, lineIndex, 0);

            int currentLeading = 0;
            if (lineLen > 0) {
                std::unique_ptr<wchar_t[]> buf(new wchar_t[lineLen + 1]);
                ((WORD*)buf.get())[0] = (WORD)(lineLen + 1);
                int len = (int)SendMessage(hEdit, EM_GETLINE, i, (LPARAM)buf.get());
                for (int j = 0; j < len; j++) {
                    if (buf[j] == L' ' || buf[j] == L'\t') currentLeading++;
                    else break;
                }
            }

            int floor = (i < (int)tab->vOriginalIndents.size())
                        ? tab->vOriginalIndents[i] : 0;

            if (currentLeading <= floor && floor > 0) {
                int msg = MessageBox(hEdit,
                    L"The selected body is in its original indent, "
                    L"do you want to overwrite and outdent it?",
                    L"!!!Protected Indent Alert!!!",
                    MB_YESNO | MB_ICONQUESTION);
                if (msg == IDYES) bUserAllowForce = true;
                else return;
                break;
            }
        }
    }

    std::wstring totalNewText;
    for (int i = startLine; i <= endLine; i++) {
        int lineIndex = (int)SendMessage(hEdit, EM_LINEINDEX, i, 0);
        int lineLen   = (int)SendMessage(hEdit, EM_LINELENGTH, lineIndex, 0);
        std::wstring lineText;

        if (lineLen > 0) {
            std::unique_ptr<wchar_t[]> buf(new wchar_t[lineLen + 1]);
            ((WORD*)buf.get())[0] = (WORD)(lineLen + 1);
            int actualLen = (int)SendMessage(hEdit, EM_GETLINE, i, (LPARAM)buf.get());
            lineText.assign(buf.get(), actualLen);
        }

        if (bOutdent) {
            int floor = bUserAllowForce ? 0 :
                        (tab && i < (int)tab->vOriginalIndents.size()
                         ? tab->vOriginalIndents[i] : 0);
            int currentLeading = 0;
            for (wchar_t c : lineText) {
                if (c == L' ' || c == L'\t') currentLeading++;
                else break;
            }
            if (currentLeading > floor) {
                int removable = currentLeading - floor;
                if (!lineText.empty() && lineText[0] == L'\t') {
                    lineText.erase(0, 1);
                } else if (!lineText.empty() && lineText[0] == L' ') {
                    int toDelete = (removable < 4) ? removable : 4;
                    int actual   = 0;
                    while (actual < toDelete && actual < (int)lineText.length()
                           && lineText[actual] == L' ')
                        actual++;
                    lineText.erase(0, actual);
                }
            }
        } else {
            lineText = L"    " + lineText;
        }

        totalNewText += lineText;
        if (i < endLine) totalNewText += L"\r\n";
    }

    int blockStart    = (int)SendMessage(hEdit, EM_LINEINDEX, startLine, 0);
    int lastLineStart = (int)SendMessage(hEdit, EM_LINEINDEX, endLine,   0);
    int lastLineLen   = (int)SendMessage(hEdit, EM_LINELENGTH, lastLineStart, 0);
    int blockEnd      = lastLineStart + lastLineLen;

    SendMessage(hEdit, WM_SETREDRAW, FALSE, 0);
    SendMessage(hEdit, EM_SETSEL, blockStart, blockEnd);
    ReplaceSelectionWithHistory(hEdit, tab, totalNewText);
    SendMessage(hEdit, EM_SETSEL, blockStart,
                blockStart + (int)totalNewText.length());

    int newFirstVisible = (int)SendMessage(hEdit, EM_GETFIRSTVISIBLELINE, 0, 0);
    SendMessage(hEdit, EM_LINESCROLL, 0, firstVisible - newFirstVisible);
    SendMessage(hEdit, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(hEdit, NULL, TRUE);
}

// =============================================================================
//  UI HELPERS
// =============================================================================
void UpdateGutter(HWND hEdit, HWND hGutter) {
    // v4.22: IsWindow guards — hGutter may have been destroyed by a
    // racing tab-close or shutdown sequence on the UI thread (e.g. a
    // cascading WM_DESTROY -> RemoveTab path).
    if (!hEdit   || !IsWindow(hEdit))   return;
    if (!hGutter || !IsWindow(hGutter)) return;
    // v4.34: bErase=FALSE eliminates the double background fill (the
    // gutter's own WM_PAINT clears with hBackBrush). UpdateWindow()
    // dropped so the WM_PAINT batches with whatever else is pending
    // — a synchronous repaint per keystroke was a measurable jank source.
    InvalidateRect(hGutter, NULL, FALSE);
}

void UpdateColInfo(HWND hEdit) {
    if (!hEdit || !hGlobalColInfo) return;
    DWORD start;
    SendMessage(hEdit, EM_GETSEL, (WPARAM)&start, 0);
    int lineIdx       = (int)SendMessage(hEdit, EM_LINEFROMCHAR, start, 0);
    int lineStartChar = (int)SendMessage(hEdit, EM_LINEINDEX,    lineIdx, 0);
    int col           = (int)start - lineStartChar + 1;
    wchar_t buf[32];
    swprintf_s(buf, 32, L"Col: %d", col);
    SetWindowText(hGlobalColInfo, buf);
}

void UpdatePieceCount(const EditorTab* tab) {
    // 1. Guard clauses & early exit for invalid state
    if (!tab || !hGlobalPieceCount || !IsWindow(hGlobalPieceCount)) {
        return;
    }

    // 2. State Tracking to prevent redundant UI updates (Flicker Reduction)
    static size_t lastCount = static_cast<size_t>(-1);
    const size_t currentCount = tab->pt.GetPieceCount();

    if (currentCount == lastCount) {
        return; 
    }
    lastCount = currentCount;

    // 3. Stack-allocated buffer with safe formatting
    wchar_t buf[64];
    // Use %Iu for portability or %zu for modern C++ standards
    int result = swprintf_s(buf, _countof(buf), L"Pieces: %zu", currentCount);

    if (result != -1) {
        // 4. Update the text. Note: WM_SETTEXT automatically triggers a repaint 
        // if the text actually changes, so manual InvalidateRect is often redundant.
        SendMessage(hGlobalPieceCount, WM_SETTEXT, 0, reinterpret_cast<LPARAM>(buf));
    }
}

void UpdateLineCount(HWND hEdit, HWND hLineCount) {
    if (!hEdit || !hLineCount) return;
    int count = (int)SendMessage(hEdit, EM_GETLINECOUNT, 0, 0);
    wchar_t buf[64];
    swprintf_s(buf, 64, L"Lines: %d", count);
    // v4.34: skip the WM_SETTEXT + invalidate when the value is
    // unchanged. Per-edit drain often sees identical counts (caret
    // motion, no-op edits) — the unconditional invalidate produced
    // a cascade of CTLCOLORSTATIC paints that added up under typing.
    static thread_local std::unordered_map<HWND, std::wstring> s_lastText;
    auto& cached = s_lastText[hLineCount];
    if (cached == buf) return;
    cached.assign(buf);
    SendMessage(hLineCount, WM_SETTEXT, 0, (LPARAM)buf);
    InvalidateRect(hLineCount, NULL, FALSE);
}

void UpdateCharacterCount(HWND hEdit, HWND hCharLabel) {
    if (!hEdit || !hCharLabel) return;
    int charCount = (int)SendMessage(hEdit, WM_GETTEXTLENGTH, 0, 0);
    wchar_t cBuf[64];
    swprintf_s(cBuf, 64, L"Chars: %d", charCount);
    // v4.34: see UpdateLineCount memo rationale.
    static thread_local std::unordered_map<HWND, std::wstring> s_lastText;
    auto& cached = s_lastText[hCharLabel];
    if (cached == cBuf) return;
    cached.assign(cBuf);
    SendMessage(hCharLabel, WM_SETTEXT, 0, (LPARAM)cBuf);
    InvalidateRect(hCharLabel, NULL, FALSE);
}

void UpdateWordCount(HWND hEdit, HWND hWordCount) {
    if (!hEdit || !hWordCount) return;

    EditorTab* tab = nullptr;
    if (IsWindow(hEdit)) {
        tab = reinterpret_cast<EditorTab*>(GetWindowLongPtr(hEdit, GWLP_USERDATA));
    }
    if (!tab) tab = GetActiveTab();

    const std::wstring emptyDoc;
    const std::wstring& doc = tab ? tab->GetDocument() : emptyDoc;

    int wordCount = 0;
    bool inWord = false;

    for (wchar_t c : doc) {
        if (c > 32) {
            if (!inWord) {
                ++wordCount;
                inWord = true;
            }
        } else {
            if (iswspace(c)) {
                inWord = false;
            } else if (c != 0) {
                if (!inWord) {
                    ++wordCount;
                    inWord = true;
                }
            }
        }
    }

    wchar_t outBuf[64];
    swprintf_s(outBuf, 64, L"Words: %d", wordCount);
    SendMessage(hWordCount, WM_SETTEXT, 0, (LPARAM)outBuf);
    InvalidateRect(hWordCount, NULL, TRUE);
    UpdateWindow(hWordCount);
}

void UpdateTitle(HWND hwnd) {
    EditorTab* tab = GetActiveTab();
    if (!tab) return;

    std::wstring title = L"| Tiny Fantail | ";
    if (tab->sFilePath.empty()) {
        title += L"Untitled";
    } else {
        fs::path p(tab->sFilePath);
        title += p.filename().wstring();
        title += L" | " + p.parent_path().wstring();
    }
    if (tab->bModified) title += L" | *Unsaved Changes* |";
    SetWindowTextW(hwnd, title.c_str());
}

int PromptForSave(HWND hwnd, EditorTab* tab) {
    if (!tab || !tab->bModified) return 0;

    std::wstring displayLabel = tab->sFilePath.empty()
        ? L"Untitled"
        : fs::path(tab->sFilePath).filename().wstring();

    std::wstring promptMsg = L"Save changes to \"" + displayLabel + L"\"?";
    int msgboxID = MessageBoxW(hwnd, promptMsg.c_str(), L"Save Changes",
                               MB_ICONQUESTION | MB_YESNOCANCEL);
    switch (msgboxID) {
        case IDYES:    return 1;
        case IDNO:     return 0;
        case IDCANCEL:
        default:       return -1;
    }
}

void RemoveTab(HWND hwnd, int index) {
    if (index < 0 || index >= (int)g_Tabs.size()) return;
    EditorTab* closingTab  = g_Tabs[index].get();
    if (!closingTab) return;
    HWND       closingEdit = closingTab->hEdit;

    // v4.40/v4.43: REAL close while async-loading.  Do not refuse the close
    // and do not delete the EditorTab under an active WM_FILE_LOAD_COMPLETE
    // stack.  Instead:
    //   1. R2  — mark the tab Closing IMMEDIATELY so any reentrant message
    //            handler that resolves it returns nullptr.
    //   2. R3  — fire the per-load cancel token so the worker bails ASAP.
    //   3.      Quarantine the tab by its LoadId, remove it from the visible
    //            tab strip, and detach the progress overlay entry so it
    //            cannot hang.  The completion/failure handler performs the
    //            final delete when the matching LoadId arrives.
    if (closingTab->bAsyncLoading) {
        // R2/O3: Closing FIRST — defends against re-entrant message dispatch
        // before the cancel propagates.
        closingTab->lifecycle.store((uint8_t)TabLifecycle::Closing,
                                    std::memory_order_release);

        LoadId loadId = closingTab->loadId;
        // R3: cancel the per-load token AND raise the global fast-path flag.
        if (closingTab->cancelToken) closingTab->cancelToken->cancel();
        g_bBulkLoadCancel.store(true, std::memory_order_release);

        if (loadId) {
            if (!TF_IsLoadAbandoned(loadId)) {
                TF_MarkLoadAbandoned(loadId);
                TF_DetachLoadFromProgress(hwnd, loadId);
            }
        } else {
            TF_DROP_LOG(L"RemoveTab: closing tab with no loadId yet (worker not started)");
        }
        closingTab->bCloseAfterAsyncLoadCancel = true;

        if (closingTab->hEdit   && IsWindow(closingTab->hEdit))   ShowWindow(closingTab->hEdit,   SW_HIDE);
        if (closingTab->hGutter && IsWindow(closingTab->hGutter)) ShowWindow(closingTab->hGutter, SW_HIDE);

        // v4.44 O1/O3: MOVE the unique_ptr into the quarantine vector.
        // Ownership transfer is type-system enforced — there is exactly one
        // owner of the tab object at any instant.
        {
            std::lock_guard<std::mutex> lk(g_AbandonedMtx);
            g_AbandonedLoadingTabs.push_back(std::move(g_Tabs[index]));
        }
        g_Tabs.erase(g_Tabs.begin() + index);   // erase the now-empty slot
        if (hGlobalTabCtrl && IsWindow(hGlobalTabCtrl) && index < TabCtrl_GetItemCount(hGlobalTabCtrl))
            TabCtrl_DeleteItem(hGlobalTabCtrl, index);

        if (g_Tabs.empty()) {
            g_ActiveTabIndex = -1;
            CreateNewTab(hwnd);
        } else {
            int oldActive = g_ActiveTabIndex;
            int newIndex = 0;
            if (oldActive == index)      newIndex = (index >= (int)g_Tabs.size()) ? (int)g_Tabs.size() - 1 : index;
            else if (oldActive > index)  newIndex = oldActive - 1;
            else                         newIndex = oldActive;
            if (newIndex < 0) newIndex = 0;
            if (newIndex >= (int)g_Tabs.size()) newIndex = (int)g_Tabs.size() - 1;
            SwitchToTab(newIndex);
        }
        UpdateTitle(hwnd);
        return;
    }

    // -------------------------------------------------------------------------
    // v4.38 — SAFE TAB CLOSE WHILE A FILE IS LOADING
    //
    // Pre-v4.38: closing a tab whose async load was still in flight (either
    // (a) the worker thread had not yet posted WM_FILE_LOAD_COMPLETE, or
    // (b) BulkSetEditText was actively chunking into closingEdit on the UI
    // thread via the message pump) would proceed to DestroyWindow(closingEdit)
    // and `delete closingTab`. Then:
    //   * the worker's queued WM_FILE_LOAD_COMPLETE would dereference the
    //     freed EditorTab*, OR
    //   * the chunk loop inside BulkSetEditText would resume after its
    //     PumpUIDuringBulkLoad() call, find IsWindow(hEdit)==FALSE on a
    //     reused HWND slot, and either crash or write into a foreign window.
    // Either way the application "just exits itself" — exactly the symptom
    // reported.
    //
    // v4.38 hardening:
    //   1. If the tab is the one currently being filled by BulkSetEditText
    //      (g_hBulkLoadingEdit == closingEdit) we raise the cooperative
    //      cancel flag and pump messages briefly until the chunk loop
    //      observes it and returns. Only then do we proceed to destroy.
    //      This makes "close the loading tab" a graceful operation instead
    //      of a crash.
    //   2. If the tab is still flagged bAsyncLoading but is NOT the active
    //      render target (meaning the worker thread is still reading from
    //      disk and hasn't posted WM_FILE_LOAD_COMPLETE yet), we refuse the
    //      close and surface a friendly message in the title bar. The user
    //      can retry once the load completes — a few-second delay is far
    //      better than a hard exit.
    //   3. We re-check the index after pumping (the in-flight cancel
    //      drains messages, which can shift tab order if WM_FILE_LOAD_*
    //      arrives for siblings).
    // -------------------------------------------------------------------------
    if (closingEdit && g_hBulkLoadingEdit.load(std::memory_order_acquire) == closingEdit) {
        // Case 1: we are mid-render into THIS tab. Signal cancel and
        // wait (bounded) for BulkSetEditText to unwind.
        g_bBulkLoadCancel.store(true, std::memory_order_release);
        for (int spin = 0; spin < 200; ++spin) {            // up to ~2 s
            if (g_hBulkLoadingEdit.load(std::memory_order_acquire) != closingEdit)
                break;
            MSG m;
            // Drain a small batch so the chunk loop's pump can run.
            for (int i = 0; i < 16 && PeekMessageW(&m, NULL, 0, 0, PM_REMOVE); ++i) {
                if (m.message == WM_QUIT) { PostQuitMessage((int)m.wParam); return; }
                TranslateMessage(&m);
                DispatchMessageW(&m);
            }
            Sleep(10);
        }
        // Re-validate: tab vector or index could have shifted while we pumped.
        if (index < 0 || index >= (int)g_Tabs.size())                return;
        if (g_Tabs[index].get() != closingTab)                        return;
        closingEdit = closingTab->hEdit;  // refresh in case it moved (unlikely)
    } else if (closingTab->bAsyncLoading) {
        // Case 2: worker thread still reading from disk. We cannot safely
        // free closingTab while a WM_FILE_LOAD_COMPLETE may already be in
        // flight referencing the matching FileLoadPayload. Politely refuse.
        FlashWindow(hwnd, TRUE);
        // Surface in the title — a MessageBox here would itself pump the
        // worker's completion and re-enter RemoveTab. The title is a
        // non-modal, allocation-free signal.
        SetWindowTextW(hwnd, L"Please wait — file is still loading. Close again when finished.");
        return;
    }


    int choice = PromptForSave(hwnd, closingTab);
    if (choice == -1) return;
    if (choice == 1) {
        int old = g_ActiveTabIndex;
        g_ActiveTabIndex = index;
        DoFileSave(hwnd);
        g_ActiveTabIndex = old;
    }

    int oldActive = g_ActiveTabIndex;
    g_ActiveTabIndex = index;
    ClearTabRamPayload(closingTab, true, true);
    g_ActiveTabIndex = oldActive;

    if (closingEdit) {
        globalSymbols.erase(
            std::remove_if(globalSymbols.begin(), globalSymbols.end(),
                [closingEdit](const Symbol& s) { return s.hTab == closingEdit; }),
            globalSymbols.end());
        g_VisibleSymbols.clear();
    }

    if (closingTab->hEdit   && IsWindow(closingTab->hEdit))   DestroyWindow(closingTab->hEdit);
    if (closingTab->hGutter && IsWindow(closingTab->hGutter)) DestroyWindow(closingTab->hGutter);

    // -------------------------------------------------------------------------
    //  Sidebar reset on tab closure.
    //
    //  Closing a tab invalidates the sidebar context that produced it: any
    //  tree items still pointing at the now-defunct workspace must be wiped
    //  before the EditorTab is destroyed.  We do this in a strict, defensive
    //  order so that no notification handler can observe a half-torn-down
    //  state:
    //    1. TreeView_DeleteAllItems   — visually clears the WC_TREEVIEW.
    //    2. g_TreeMap.clear()          — releases all stored path strings.
    //    3. g_TreeRootDir.clear()      — invalidates the cached root path,
    //                                    forcing a full async reload next time.
    // -------------------------------------------------------------------------
    if (g_hDirTree && IsWindow(g_hDirTree)) {
        SendMessage(g_hDirTree, WM_SETREDRAW, FALSE, 0);
        TreeView_DeleteAllItems(g_hDirTree);
        SendMessage(g_hDirTree, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(g_hDirTree, NULL, TRUE);
    }
    g_TreeMap.clear();
    g_TreeRootDir.clear();

    // v4.43 R2 / v4.44 O1: mark Dead + drop from side-table BEFORE the
    // unique_ptr scope exits, so any racing message handler that resolves
    // a stale TabHandle returns null.  No raw `delete` — the erase()
    // below runs the unique_ptr destructor, which is the ONLY sanctioned
    // free path for an EditorTab.
    closingTab->lifecycle.store((uint8_t)TabLifecycle::Dead, std::memory_order_release);
    closingTab->loadId = 0;   // O2: any late payload fails cross-check
    TF_UnregisterTab(closingTab);
    g_Tabs.erase(g_Tabs.begin() + index);   // unique_ptr dtor here
    TabCtrl_DeleteItem(hGlobalTabCtrl, index);
    TrimProcessRamNow();

    if (g_Tabs.empty()) {
        g_ActiveTabIndex = -1;
        CreateNewTab(hwnd);
    } else {
        int newIndex = (index >= (int)g_Tabs.size()) ? (int)g_Tabs.size() - 1 : index;
        SwitchToTab(newIndex);
    }
    TrimProcessRamNow();
}

void OnEditCompact(HWND hwnd) {
    TF_AssertUIThread();   // v4.26
    EditorTab* active = GetActiveTab();

    // Intelligence: Guard against null and check if compaction is even necessary
    if (!active) return;

    size_t countBefore = active->pt.GetPieceCount();

    // Performance check: If it's already 1 piece (or 0), compacting is a waste of cycles
    if (countBefore <= 1) {
        // v4.26: still reset the auto-compact counters so the watchdog does
        // not keep re-checking a tab that is already in canonical form.
        active->editsSinceCompact    = 0;
        active->lastCompactNodeCount = countBefore;
        return;
    }

    // v4.26: re-entrancy guard — same MutationGuard the auto-compactor uses.
    MutationGuard lock(active);
    if (!lock.acquired()) return;

    // Execute the core logic
    active->pt.Compact();

    // v4.26: keep auto-compact counters in sync with reality.
    active->editsSinceCompact    = 0;
    active->lastCompactNodeCount = active->pt.GetPieceCount();
    active->cachedDocDirty       = true;

    // Intelligence: Only update the UI and notify the user if something actually changed
    size_t countAfter = active->pt.GetPieceCount();
    if (countAfter < countBefore) {
        UpdatePieceCount(active);

        // Optional: Provide a subtle status bar hint or sound to acknowledge the Hotkey
        // MessageBeep(MB_OK);
    }
}

// =============================================================================
// v4.37 SURGICAL UPGRADE — Hardened Ctrl +/- font resize with progress overlay
//
// Reuses the v4.36 fixed-size load progress panel as a generic "task overlay".
// The relayout loop iterates over every tab (potentially dozens of huge docs)
// and each WM_SETFONT triggers a heavy edit-control re-measure. On a machine
// with many large tabs this can take seconds — the user must see progress,
// not a frozen UI.
//
// Hardening goals (all behaviour-preserving for the happy path):
//   H1. GDI LEAK SAFETY
//       The newly-created HFONT is owned by a local RAII guard until every
//       tab has accepted it via WM_SETFONT. Only on full success do we
//       transfer ownership to the global hEditorFont and free the OLD font.
//       On ANY failure (CreateFont returns NULL, exception in the loop,
//       shutdown mid-loop) the new font is destroyed by the guard's dtor
//       and the old font remains the live one — zero GDI leak.
//   H2. REENTRANCY GUARD
//       A thread_local bool prevents Ctrl-+/- autorepeat from re-entering
//       UpdateEditorFont while a previous resize is still mid-flight (the
//       message pump runs during the per-tab WM_SETFONT). v4.35 could leak
//       HFONTs and double-resize on rapid autorepeat; v4.37 cannot.
//   H3. CRASH SAFETY
//       Every tab pointer is null/IsWindow-validated before use. Exceptions
//       in the per-tab loop (std::bad_alloc from gutter relayout, etc.) are
//       caught; the loop continues so one bad tab cannot abort the rest.
//   H4. DATA INTEGRITY
//       nCurrentFontSize is committed only on full success. If CreateFont
//       fails we keep the OLD size so persisted prefs cannot drift away
//       from the live HFONT.
//   H5. PROGRESS UI
//       The v4.36 fixed-size overlay is driven from this loop so the user
//       sees "Resizing text layout — tab N/M  ·  XX%". Hidden via
//       HideLoadProgressUI(hMain) so the area underneath repaints cleanly.
// =============================================================================

namespace TF_FontResize {

// RAII guard for a transient HFONT we may need to abandon on the error path.
struct ScopedHFontOwner {
    HFONT h{NULL};
    ScopedHFontOwner() = default;
    explicit ScopedHFontOwner(HFONT x) noexcept : h(x) {}
    ~ScopedHFontOwner() noexcept { if (h) { ::DeleteObject(h); h = NULL; } }
    HFONT release() noexcept { HFONT t = h; h = NULL; return t; }
    ScopedHFontOwner(const ScopedHFontOwner&)            = delete;
    ScopedHFontOwner& operator=(const ScopedHFontOwner&) = delete;
};

// Render a fixed-format progress caption directly into the v4.36 overlay's
// two label rows + bar. We bypass TF_RenderLoadLabel here because that one
// is keyed off the file-load registry; the resize task is synthetic.
static void RenderProgress(HWND hMainWnd, int tabIndex, int tabTotal, int newSize) {
    if (!g_hLoadProgressPanel || !IsWindow(g_hLoadProgressPanel)) return;
    LayoutLoadProgressPanel(hMainWnd);  // re-pin fixed size every tick (H+F1)

    int pct = (tabTotal > 0)
        ? (int)((100LL * (long long)tabIndex) / (long long)tabTotal)
        : 100;
    if (pct < 0) pct = 0; if (pct > 100) pct = 100;

    if (g_hLoadProgressBar && IsWindow(g_hLoadProgressBar))
        SendMessageW(g_hLoadProgressBar, PBM_SETPOS, (WPARAM)pct, 0);

    wchar_t row1[256] = {0};
    wchar_t row2[128] = {0};
    _snwprintf_s(row1, _countof(row1), _TRUNCATE,
                 L"Resizing text layout  (font %d pt)", newSize);
    _snwprintf_s(row2, _countof(row2), _TRUNCATE,
                 L"Relayout  ·  tab %d / %d  ·  %d%%",
                 tabIndex, tabTotal, pct);

    if (g_hLoadProgressLabel  && IsWindow(g_hLoadProgressLabel))
        SetWindowTextW(g_hLoadProgressLabel,  row1);
    if (g_hLoadProgressLabel2 && IsWindow(g_hLoadProgressLabel2))
        SetWindowTextW(g_hLoadProgressLabel2, row2);
}

} // namespace TF_FontResize

void UpdateEditorFont(HWND hEdit, HWND hGutter, int newSize) {
    // H4: clamp early but DO NOT commit nCurrentFontSize until full success.
    if (newSize < 8)  newSize = 8;
    if (newSize > 72) newSize = 72;

    // H2: thread-local reentrancy guard. Ctrl-+ autorepeat + the message
    // pump that runs during WM_SETFONT made re-entry possible in v4.35,
    // which would leak HFONTs and double-resize. Reject the inner call.
    static thread_local bool s_inUpdateFont = false;
    if (s_inUpdateFont) return;
    struct ReentryGuard {
        bool* flag;
        explicit ReentryGuard(bool* f) noexcept : flag(f) { *flag = true; }
        ~ReentryGuard() noexcept { *flag = false; }
    } _rg(&s_inUpdateFont);

    // No-op on a redundant call — saves a full GDI round-trip and avoids
    // flashing the progress overlay.
    if (newSize == nCurrentFontSize && hEditorFont) return;

    // H1: create the new font into a RAII guard. If anything below fails
    // or throws, the destructor releases the GDI handle — no leak possible.
    TF_FontResize::ScopedHFontOwner newFontGuard(
        CreateFontW(newSize, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                    CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas"));
    if (!newFontGuard.h) {
        // CreateFont failed — keep old font live and bail. nCurrentFontSize
        // stays put so persisted prefs remain consistent (H4).
        return;
    }

    // Resolve the main window once, for overlay + post-resize WM_SIZE reflow.
    HWND hMainWnd = NULL;
    if (hGlobalTabCtrl) hMainWnd = GetParent(hGlobalTabCtrl);
    if (!hMainWnd && hEdit && IsWindow(hEdit))
        hMainWnd = GetAncestor(hEdit, GA_ROOT);

    // H5: only show the overlay when the relayout will actually be visible.
    // For a single tiny tab the work is sub-frame and an overlay would just
    // flicker. Threshold is intentionally conservative.
    const int tabTotal = (int)g_Tabs.size();
    bool showOverlay = false;
    if (hMainWnd && tabTotal > 0) {
        if (tabTotal >= 2) {
            showOverlay = true;
        } else if (g_Tabs[0] && g_Tabs[0]->hEdit && IsWindow(g_Tabs[0]->hEdit)) {
            int len = GetWindowTextLengthW(g_Tabs[0]->hEdit);
            if (len > 200000) showOverlay = true;  // ~200 KB doc threshold
        }
    }
    if (showOverlay) {
        EnsureLoadProgressUI(hMainWnd);
        if (g_hLoadProgressPanel && IsWindow(g_hLoadProgressPanel)) {
            ShowWindow(g_hLoadProgressPanel, SW_SHOWNA);
            TF_FontResize::RenderProgress(hMainWnd, 0, tabTotal, newSize);
        } else {
            showOverlay = false;  // creation failed — proceed without UI
        }
    }

    // H1+H3: apply the new font to every tab. The HFONT is owned by
    // newFontGuard for the entire loop — on a partial failure (exception
    // mid-loop) the dtor frees it and the OLD global font remains live.
    int processed = 0;
    int failed    = 0;
    for (auto& upTab : g_Tabs) {
        EditorTab* tab = upTab.get();
        ++processed;
        try {
            if (!tab) { ++failed; continue; }
            if (tab->hEdit   && IsWindow(tab->hEdit))
                SendMessageW(tab->hEdit,   WM_SETFONT, (WPARAM)newFontGuard.h, MAKELPARAM(TRUE, 0));
            if (tab->hGutter && IsWindow(tab->hGutter))
                SendMessageW(tab->hGutter, WM_SETFONT, (WPARAM)newFontGuard.h, MAKELPARAM(TRUE, 0));
            if (tab->hEdit && tab->hGutter
                && IsWindow(tab->hEdit) && IsWindow(tab->hGutter)) {
                UpdateGutter(tab->hEdit, tab->hGutter);
            }
        } catch (...) {
            // H3: a single bad tab cannot abort the resize. Keep going so
            // the user's other tabs end up consistent.
            ++failed;
        }
        if (showOverlay)
            TF_FontResize::RenderProgress(hMainWnd, processed, tabTotal, newSize);
    }

    // H1: ALL tabs done — now publish the new font globally and free the
    // old one. Order matters: publish first so any racing paint sees the
    // new pointer, THEN delete the old GDI object.
    HFONT hOldFont   = hEditorFont;
    hEditorFont      = newFontGuard.release();   // global takes ownership
    nCurrentFontSize = newSize;                  // H4: commit only on success
    if (hOldFont) DeleteObject(hOldFont);

    // Trigger main-window WM_SIZE so the splitter/gutter widths re-flow.
    if (hMainWnd) {
        RECT rc; GetClientRect(hMainWnd, &rc);
        PostMessageW(hMainWnd, WM_SIZE, 0, MAKELPARAM(rc.right, rc.bottom));
    }

    // Tear the overlay down. HideLoadProgressUI(hMainWnd) invalidates the
    // rect underneath so the gutter/editor repaint cleanly (no ghost).
    if (showOverlay) HideLoadProgressUI(hMainWnd);

    (void)failed;  // reserved for future telemetry; intentionally unused.
}

// =============================================================================
//  v4.27 — Bracket matching that respects C/C++ literals & comments.
//
//  Earlier revisions counted every '{' / '}' / '(' / ')' / '[' / ']' character
//  in the buffer.  In a real source file that produces phantom mismatches
//  whenever a bracket appears inside:
//      • a string literal       "...{...}"
//      • a wide/UTF char literal L'{', u'{', U'{', u8'{'
//      • a line comment         // foo { bar
//      • a block comment        /* foo { bar */
//
//  The fix is a tiny single-pass C/C++ lexer that classifies every wchar_t
//  as either CODE or NON-CODE (literal/comment).  Bracket counting only
//  looks at CODE characters.  The lexer recognises:
//      • // line comments (terminated by \n)
//      • /* block comments (terminated by */ ; not nested, per C/C++)
//      • "..." string literals with backslash escapes
//      • '...' char literals with backslash escapes
//      • optional encoding prefixes L / u / U / u8 immediately preceding ' or "
//      • raw string literals R"delim(...)delim"  (and L/u/U/u8 prefixes)
//
//  It is deliberately NOT a full C++ tokenizer — no preprocessor, no
//  digraphs, no UCNs — just enough to keep bracket counts honest in real
//  code.  False positives (treating a string-like sequence as code) are
//  preferred over false negatives, so anything we are unsure about stays
//  CODE.
// =============================================================================

namespace tf_bracket_lex {

enum class LexState : unsigned char {
    Code,           // ordinary code
    LineComment,    // inside //
    BlockComment,   // inside /*
    String,         // inside "
    Char,           // inside '
    RawString       // inside R"delim( ... )delim"
};

// Returns true if `c` may appear immediately before ' or " as an encoding
// prefix character (L, u, U, or the '8' of u8).  We treat any of these
// loosely; precise prefix parsing is unnecessary for bracket counting.
inline bool IsEncodingPrefixChar(wchar_t c) {
    return c == L'L' || c == L'u' || c == L'U' || c == L'8' || c == L'R';
}

// Single-step lexer.  Caller drives it character-by-character; we mutate
// `st` and (for raw strings) `rawDelim`.  `prev` is the previously seen
// character (for detecting "*/", "\\\"", etc.).  Returns true if the
// character at this position should be treated as CODE for the purpose
// of bracket counting.
inline bool StepIsCode(wchar_t c, wchar_t next, LexState& st,
                       std::wstring& rawDelim, bool& escape,
                       bool& rawCollectingDelim) {
    switch (st) {
    case LexState::Code: {
        // Detect comment / string / char openers.
        if (c == L'/' && next == L'/') { st = LexState::LineComment;  return false; }
        if (c == L'/' && next == L'*') { st = LexState::BlockComment; return false; }
        if (c == L'"') {
            st = LexState::String; escape = false;
            return false;
        }
        if (c == L'\'') {
            st = LexState::Char; escape = false;
            return false;
        }
        // Raw string: a preceding 'R' followed by '"' is the trigger.  We
        // only flip to RawString when we see the '"', and we treat the 'R'
        // itself as code (harmless — 'R' is never a bracket).
        return true;
    }
    case LexState::LineComment:
        if (c == L'\n') st = LexState::Code;
        return false;
    case LexState::BlockComment:
        // We only close on the '/' of a "*/" pair.  The '*' was the prev char.
        if (c == L'/' && /*prev==*/ false) {} // unused; handled below
        return false;
    case LexState::String:
        if (escape)              { escape = false; return false; }
        if (c == L'\\')          { escape = true;  return false; }
        if (c == L'"')           { st = LexState::Code; }
        if (c == L'\n')          { st = LexState::Code; } // unterminated — recover
        return false;
    case LexState::Char:
        if (escape)              { escape = false; return false; }
        if (c == L'\\')          { escape = true;  return false; }
        if (c == L'\'')          { st = LexState::Code; }
        if (c == L'\n')          { st = LexState::Code; } // unterminated — recover
        return false;
    case LexState::RawString:
        // Look for terminator: ) <delim> "
        // Caller handles this in the dedicated raw-string branch.
        return false;
    }
    return true;
}

} // namespace tf_bracket_lex

// -----------------------------------------------------------------------------
//  Build a bitmap (one bit per wchar_t) flagging which positions in `text`
//  are CODE (true) vs literal/comment (false).  Single forward pass, O(N).
//  `startState` lets a chunked caller resume from a known mid-document state.
//  `endState` (out) reports the lexer state at the end of `text` so the
//  caller can pass it back in for the next chunk.
// -----------------------------------------------------------------------------
static void BuildCodeMask(const wchar_t* text, size_t len,
                          std::vector<bool>& isCode,
                          tf_bracket_lex::LexState& state) {
    using tf_bracket_lex::LexState;
    isCode.assign(len, false);
    bool escape = false;

    for (size_t i = 0; i < len; ++i) {
        wchar_t c    = text[i];
        wchar_t next = (i + 1 < len) ? text[i + 1] : L'\0';

        switch (state) {
        case LexState::Code:
            if (c == L'/' && next == L'/') { state = LexState::LineComment; isCode[i] = false; }
            else if (c == L'/' && next == L'*') { state = LexState::BlockComment; isCode[i] = false; }
            else if (c == L'"') { state = LexState::String;  escape = false; isCode[i] = false; }
            else if (c == L'\'') { state = LexState::Char;   escape = false; isCode[i] = false; }
            else { isCode[i] = true; }
            break;
        case LexState::LineComment:
            isCode[i] = false;
            if (c == L'\n') state = LexState::Code;
            break;
        case LexState::BlockComment:
            isCode[i] = false;
            if (c == L'/' && i > 0 && text[i - 1] == L'*') state = LexState::Code;
            break;
        case LexState::String:
            isCode[i] = false;
            if (escape)        { escape = false; }
            else if (c == L'\\') { escape = true; }
            else if (c == L'"')  { state = LexState::Code; }
            else if (c == L'\n') { state = LexState::Code; } // recover from unterminated
            break;
        case LexState::Char:
            isCode[i] = false;
            if (escape)        { escape = false; }
            else if (c == L'\\') { escape = true; }
            else if (c == L'\'') { state = LexState::Code; }
            else if (c == L'\n') { state = LexState::Code; } // recover from unterminated
            break;
        case LexState::RawString:
            // Not constructed in this lexer — see note in header.
            isCode[i] = false;
            if (c == L'"') state = LexState::Code;
            break;
        }
    }
}

int FindMatchingBracket(const wstring& text, int pos) {
    if (pos < 0 || pos >= (int)text.length()) return -1;
    wchar_t open = text[pos], close;
    int direction = 1;

    if      (open == L'(') close = L')';
    else if (open == L'{') close = L'}';
    else if (open == L'[') close = L']';
    else if (open == L')') { close = L'('; direction = -1; }
    else if (open == L'}') { close = L'{'; direction = -1; }
    else if (open == L']') { close = L'['; direction = -1; }
    else return -1;

    // Build CODE mask over the entire window once.  O(N) one-shot — fine
    // because the caller (WM_PAINT) only invokes us on the visible window.
    std::vector<bool> isCode;
    tf_bracket_lex::LexState st = tf_bracket_lex::LexState::Code;
    BuildCodeMask(text.c_str(), text.size(), isCode, st);

    // The seed bracket itself must be CODE; if it sits inside a literal /
    // comment there is no meaningful partner to find here.
    if (!isCode[(size_t)pos]) return -1;

    int stack = 1;
    for (int i = pos + direction;
         i >= 0 && i < (int)text.length();
         i += direction) {
        if (!isCode[(size_t)i]) continue;        // skip literal / comment chars
        if      (text[i] == open)  stack++;
        else if (text[i] == close) stack--;
        if (stack == 0) return i;
    }
    return -1;
}

// =============================================================================
//  v4.16 — Whole-document bracket matching (piece-table aware overload).
//  v4.27 — Now lexer-aware: brackets inside strings / chars / comments are
//          ignored, matching the on-screen scanner above.
//
//  Scans the ENTIRE document for the partner of the bracket at absolute
//  character offset `absPos`, walking the piece table in fixed-size chunks
//  via PieceTable::GetVirtualSpan().  Bounded peak memory (CHUNK wchar_t per
//  span) regardless of document size or nesting depth, so off-screen pairs
//  hundreds of screens away resolve without materialising the whole doc.
//
//  The lexer state is THREADED across chunk boundaries via `state`, so a
//  block comment or string straddling a 64K chunk boundary is handled
//  correctly.
//
//  For the REVERSE direction we cannot lex right-to-left, so we lex
//  forward from offset 0 up to `absPos` once to learn which positions in
//  [0, absPos) are code, then scan that buffer backwards.  This bounds
//  peak memory at O(absPos) bits for the mask plus one chunk of text at a
//  time — acceptable; the reverse path is the rare case (caret on a
//  closing bracket that needs to find its opener).
//
//  Returns the absolute character index of the partner, or -1 if no match
//  / not a bracket / seed bracket sits inside a literal or comment.
// =============================================================================
int FindMatchingBracketAbs(PieceTable& pt, size_t absPos) {
    using tf_bracket_lex::LexState;

    const size_t docLen = pt.Length();
    if (absPos >= docLen) return -1;

    // Materialise just the seed character to learn open/close/direction.
    wstring seed = pt.GetVirtualSpan(absPos, 1);
    if (seed.empty()) return -1;
    wchar_t open = seed[0], close;
    int direction = 1;

    if      (open == L'(') close = L')';
    else if (open == L'{') close = L'}';
    else if (open == L'[') close = L']';
    else if (open == L')') { close = L'('; direction = -1; }
    else if (open == L'}') { close = L'{'; direction = -1; }
    else if (open == L']') { close = L'['; direction = -1; }
    else return -1;

    static constexpr size_t CHUNK = 64 * 1024;  // wchar_t per span request

    // ---------------------------------------------------------------------
    //  Step 1 — lex forward from position 0 up to absPos to learn the lexer
    //  state AT the seed, AND (only for the reverse direction) record the
    //  CODE/NON-CODE classification of every position in [0, absPos).
    // ---------------------------------------------------------------------
    LexState seedState = LexState::Code;
    bool     escape    = false;
    std::vector<bool> preMask;     // populated only when direction == -1
    if (direction == -1) preMask.reserve(absPos);

    {
        size_t cursor = 0;
        while (cursor < absPos) {
            size_t take = (absPos - cursor < CHUNK) ? (absPos - cursor) : CHUNK;
            wstring chunk = pt.GetVirtualSpan(cursor, take);
            if (chunk.empty()) break;
            for (size_t k = 0; k < chunk.size(); ++k) {
                wchar_t c    = chunk[k];
                wchar_t next = (k + 1 < chunk.size())
                                 ? chunk[k + 1]
                                 // Cross-chunk peek: fetch one more char if needed.
                                 : (cursor + k + 1 < absPos
                                       ? pt.GetVirtualSpan(cursor + k + 1, 1)[0]
                                       : L'\0');
                bool code = false;
                switch (seedState) {
                case LexState::Code:
                    if (c == L'/' && next == L'/') { seedState = LexState::LineComment; }
                    else if (c == L'/' && next == L'*') { seedState = LexState::BlockComment; }
                    else if (c == L'"')  { seedState = LexState::String; escape = false; }
                    else if (c == L'\'') { seedState = LexState::Char;   escape = false; }
                    else                  { code = true; }
                    break;
                case LexState::LineComment:
                    if (c == L'\n') seedState = LexState::Code;
                    break;
                case LexState::BlockComment: {
                    // close on '/' preceded by '*'
                    wchar_t prev = (k > 0) ? chunk[k - 1]
                                           : (cursor > 0 ? pt.GetVirtualSpan(cursor - 1, 1)[0]
                                                         : L'\0');
                    if (c == L'/' && prev == L'*') seedState = LexState::Code;
                    break;
                }
                case LexState::String:
                    if (escape)         escape = false;
                    else if (c == L'\\') escape = true;
                    else if (c == L'"')  seedState = LexState::Code;
                    else if (c == L'\n') seedState = LexState::Code;
                    break;
                case LexState::Char:
                    if (escape)         escape = false;
                    else if (c == L'\\') escape = true;
                    else if (c == L'\'') seedState = LexState::Code;
                    else if (c == L'\n') seedState = LexState::Code;
                    break;
                case LexState::RawString:
                    if (c == L'"') seedState = LexState::Code;
                    break;
                }
                if (direction == -1) preMask.push_back(code);
            }
            cursor += chunk.size();
        }
    }

    // The seed bracket itself must be in CODE state.
    if (seedState != LexState::Code) return -1;

    int stack = 1;

    if (direction == 1) {
        // ---- Forward scan: lex incrementally as we go. ------------------
        LexState st = LexState::Code;       // state AT (absPos+1) — same as seedState
        // Re-derive: after consuming the seed bracket (which we know is CODE)
        // the state is unchanged.  st starts at Code.
        st = seedState;                     // == Code
        bool esc = false;

        size_t cursor = absPos + 1;
        while (cursor < docLen) {
            size_t take  = (docLen - cursor < CHUNK) ? (docLen - cursor) : CHUNK;
            wstring chunk = pt.GetVirtualSpan(cursor, take);
            if (chunk.empty()) break;
            for (size_t k = 0; k < chunk.size(); ++k) {
                wchar_t c    = chunk[k];
                wchar_t next = (k + 1 < chunk.size())
                                 ? chunk[k + 1]
                                 : (cursor + k + 1 < docLen
                                       ? pt.GetVirtualSpan(cursor + k + 1, 1)[0]
                                       : L'\0');
                bool code = false;
                switch (st) {
                case LexState::Code:
                    if      (c == L'/' && next == L'/') { st = LexState::LineComment; }
                    else if (c == L'/' && next == L'*') { st = LexState::BlockComment; }
                    else if (c == L'"')  { st = LexState::String; esc = false; }
                    else if (c == L'\'') { st = LexState::Char;   esc = false; }
                    else                  { code = true; }
                    break;
                case LexState::LineComment:
                    if (c == L'\n') st = LexState::Code;
                    break;
                case LexState::BlockComment: {
                    wchar_t prev = (k > 0) ? chunk[k - 1]
                                           : pt.GetVirtualSpan(cursor + k - 1, 1)[0];
                    if (c == L'/' && prev == L'*') st = LexState::Code;
                    break;
                }
                case LexState::String:
                    if (esc)            esc = false;
                    else if (c == L'\\') esc = true;
                    else if (c == L'"')  st = LexState::Code;
                    else if (c == L'\n') st = LexState::Code;
                    break;
                case LexState::Char:
                    if (esc)            esc = false;
                    else if (c == L'\\') esc = true;
                    else if (c == L'\'') st = LexState::Code;
                    else if (c == L'\n') st = LexState::Code;
                    break;
                case LexState::RawString:
                    if (c == L'"') st = LexState::Code;
                    break;
                }
                if (code) {
                    if      (c == open)  stack++;
                    else if (c == close) stack--;
                    if (stack == 0) return (int)(cursor + k);
                }
            }
            cursor += chunk.size();
        }
    } else {
        // ---- Reverse scan: walk preMask backwards. ----------------------
        // preMask[i] tells whether absolute position i (for i in [0,absPos))
        // is CODE.  We need the actual character at each CODE position.
        // Pull text in chunks right-to-left, mirroring the original loop.
        size_t cursorEnd = absPos;
        while (cursorEnd > 0) {
            size_t take    = (cursorEnd < CHUNK) ? cursorEnd : CHUNK;
            size_t chunkBeg = cursorEnd - take;
            wstring chunk   = pt.GetVirtualSpan(chunkBeg, take);
            if (chunk.empty()) break;
            for (size_t k = chunk.size(); k-- > 0; ) {
                size_t abs = chunkBeg + k;
                if (abs >= preMask.size() || !preMask[abs]) continue;
                wchar_t c = chunk[k];
                if      (c == open)  stack++;
                else if (c == close) stack--;
                if (stack == 0) return (int)abs;
            }
            cursorEnd = chunkBeg;
        }
    }
    return -1;
}

void DoSearchText(HWND hwnd, HWND hSearchInput, bool searchUp) {
    EditorTab* tab = GetActiveTab();
    if (!tab) return;

    wchar_t searchBuf[256];
    GetWindowText(hSearchInput, searchBuf, 256);
    wstring searchKey = searchBuf;
    if (searchKey.empty()) return;

    // Use the piece table's virtual text — avoids a GetWindowText allocation.
    const std::wstring& content = tab->GetDocument();
    if (content.empty()) {
        MessageBox(hwnd, L"No matches found.", L"Search", MB_OK | MB_ICONINFORMATION);
        return;
    }

    wstring lowerContent = content;
    wstring lowerKey     = searchKey;
    transform(lowerContent.begin(), lowerContent.end(), lowerContent.begin(), ::towlower);
    transform(lowerKey.begin(),     lowerKey.end(),     lowerKey.begin(),     ::towlower);

    size_t firstOccur = lowerContent.find(lowerKey);
    if (firstOccur == wstring::npos) {
        MessageBox(hwnd, L"No matches found.", L"Search", MB_OK | MB_ICONINFORMATION);
        return;
    }
    size_t lastOccur = lowerContent.rfind(lowerKey);

    DWORD start, end;
    SendMessage(tab->hEdit, EM_GETSEL, (WPARAM)&start, (LPARAM)&end);
    size_t found = wstring::npos;

    if (searchUp) {
        if (start > 0) found = lowerContent.rfind(lowerKey, start - 1);
        if (found == wstring::npos) {
            MessageBox(hwnd,
                L"Reached the beginning of the file. Wrapping to the bottom.",
                L"Search", MB_OK | MB_ICONEXCLAMATION);
            found = lastOccur;
        } else if (found == firstOccur) {
            MessageBox(hwnd, L"This is the first occurrence in the file.",
                       L"Search", MB_OK | MB_ICONINFORMATION);
        }
    } else {
        found = lowerContent.find(lowerKey, end);
        if (found == wstring::npos) {
            MessageBox(hwnd,
                L"Reached the end of the file. Wrapping to the top.",
                L"Search", MB_OK | MB_ICONEXCLAMATION);
            found = firstOccur;
        } else if (found == lastOccur) {
            MessageBox(hwnd, L"This is the last occurrence in the file.",
                       L"Search", MB_OK | MB_ICONINFORMATION);
        }
    }

    if (found != wstring::npos) {
        SendMessage(tab->hEdit, EM_SETSEL,
                    (WPARAM)found, (LPARAM)(found + searchKey.length()));
        SendMessage(tab->hEdit, EM_SCROLLCARET, 0, 0);
        UpdateGutter(tab->hEdit, tab->hGutter);
        SetFocus(tab->hEdit);
    }
}

// WriteFileContent — reads the virtual document from the Piece Table;
// avoids a redundant GetWindowText when the PT is up-to-date.
bool WriteFileContent(const wstring& path, EditorTab* tab) {
    // ── v4.41 hardened save pipeline ────────────────────────────────────
    //  Order of operations (each step must succeed before the next):
    //    1. Materialise the document text from the piece table (or sync
    //       it from the EDIT control if ptDirty).
    //    2. Encode to UTF-8.  Hash both wide and UTF-8 representations
    //       so we can verify after the round trip.
    //    3. Snapshot the EXISTING file (if any) to "<path>.bak".  Failure
    //       here is non-fatal — first-time saves have no original.
    //    4. Write to "<path>.tmp" with FILE_FLAG_WRITE_THROUGH semantics
    //       (CREATE_ALWAYS + FlushFileBuffers).
    //    5. Atomic rename via MoveFileExW(MOVEFILE_REPLACE_EXISTING |
    //       MOVEFILE_WRITE_THROUGH).
    //    6. RE-READ "<path>" from disk and verify (length, FNV-1a-64).
    //       If verification fails, restore from "<path>.bak" and refuse
    //       to mark the tab clean.
    //    7. On success, stamp tab->lastDiskHash + lastDiskBytes and
    //       delete the autosave .recover snapshot.
    // ────────────────────────────────────────────────────────────────────
    std::wstring docText;
    if (!tab->ptDirty) {
        docText = tab->pt.GetVirtualText();
    } else {
        int len = GetWindowTextLength(tab->hEdit);
        docText.resize(len + 1, L'\0');
        GetWindowText(tab->hEdit, &docText[0], len + 1);
        docText.resize(len);
        tab->pt.LoadOriginal(docText);
        tab->ptDirty = false;
    }

    if (docText.size() > (size_t)std::numeric_limits<int>::max()) {
        MessageBoxW(GetAncestor(tab->hEdit, GA_ROOT),
                    L"Document is too large to encode safely.", L"Save Error",
                    MB_OK | MB_ICONERROR);
        return false;
    }

    int utf8_len = WideCharToMultiByte(CP_UTF8, 0,
                                        docText.data(), (int)docText.size(),
                                        NULL, 0, NULL, NULL);
    if (!docText.empty() && utf8_len <= 0) {
        MessageBoxW(GetAncestor(tab->hEdit, GA_ROOT),
                    L"Could not encode document as UTF-8.", L"Save Error",
                    MB_OK | MB_ICONERROR);
        return false;
    }

    std::vector<char> utf8_buf((size_t)utf8_len);
    if (utf8_len > 0) {
        WideCharToMultiByte(CP_UTF8, 0,
                            docText.data(), (int)docText.size(),
                            utf8_buf.data(), utf8_len, NULL, NULL);
    }

    // Pre-compute the expected on-disk shape so verification (step 6) is
    // a pure byte comparison — no second encode required.
    const uint64_t expectedBytes = (uint64_t)utf8_buf.size();
    const uint64_t expectedHash  = tf_v441::Reliability::Fnv1a64(
                                       utf8_buf.data(), utf8_buf.size());

    // Step 3 — backup-ring rotation.  Best effort; first-time saves skip.
    bool hadBackup = tf_v441::Reliability::BackupExistingFile(path);

    // Step 4 — temp file write + flush.
    std::wstring tmpPath;
    try { tmpPath = path + L".tmp"; }
    catch (...) {
        MessageBoxW(GetAncestor(tab->hEdit, GA_ROOT),
                    L"Out of memory preparing save.", L"Save Error",
                    MB_OK | MB_ICONERROR);
        return false;
    }

    HANDLE hFile = CreateFileW(tmpPath.c_str(), GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        MessageBoxW(GetAncestor(tab->hEdit, GA_ROOT),
                    L"Could not open temp file for writing.", L"Save Error",
                    MB_OK | MB_ICONERROR);
        return false;
    }

    bool writeOk = true;
    size_t totalWritten = 0;
    while (writeOk && totalWritten < utf8_buf.size()) {
        DWORD chunk = (DWORD)std::min<size_t>(utf8_buf.size() - totalWritten, MAXDWORD);
        DWORD written = 0;
        if (!WriteFile(hFile, utf8_buf.data() + totalWritten, chunk, &written, NULL) ||
            written == 0) {
            writeOk = false;
            break;
        }
        totalWritten += written;
    }
    if (writeOk) writeOk = (FlushFileBuffers(hFile) != FALSE);
    if (!CloseHandle(hFile)) writeOk = false;

    if (!writeOk) {
        _wremove(tmpPath.c_str());
        MessageBoxW(GetAncestor(tab->hEdit, GA_ROOT),
                    L"Disk write failed.", L"Save Error", MB_OK | MB_ICONERROR);
        return false;
    }

    // Step 5 — atomic replace.
    if (!MoveFileExW(tmpPath.c_str(), path.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        _wremove(tmpPath.c_str());
        wchar_t errMsg[MAX_PATH + 64];
        swprintf_s(errMsg, L"Could not replace file. Error code: %lu", GetLastError());
        MessageBoxW(GetAncestor(tab->hEdit, GA_ROOT), errMsg, L"Save Error",
                    MB_OK | MB_ICONERROR);
        return false;
    }

    // Step 6 — read-back verification.  If the bytes on disk do not match
    // what we just wrote, we have either a driver bug, antivirus rewrite,
    // network filesystem corruption, or hardware problem.  Roll back from
    // the .bak (if we made one) and refuse to mark the tab clean.
    uint64_t gotBytes = 0, gotHash = 0;
    if (!tf_v441::Reliability::ReadBackHash(path, gotBytes, gotHash) ||
        gotBytes != expectedBytes || gotHash != expectedHash) {
        if (hadBackup) {
            tf_v441::Reliability::RestoreFromBackup(path);
            MessageBoxW(GetAncestor(tab->hEdit, GA_ROOT),
                L"Save verification FAILED.\n\n"
                L"The bytes on disk do not match the document in memory.\n"
                L"Your previous file has been restored from <path>.bak.\n"
                L"Try saving to a different location.",
                L"Save Aborted - Disk Verification Failed",
                MB_OK | MB_ICONERROR);
        } else {
            MessageBoxW(GetAncestor(tab->hEdit, GA_ROOT),
                L"Save verification FAILED.\n\n"
                L"The bytes on disk do not match the document in memory.\n"
                L"No previous version was available to restore from.\n"
                L"Try saving to a different location.",
                L"Save Aborted - Disk Verification Failed",
                MB_OK | MB_ICONERROR);
        }
        return false;
    }

    // Step 7 — record on-disk fingerprint, delete recover snapshot.
    tab->lastDiskBytes = gotBytes;
    tab->lastDiskHash  = gotHash;
    tab->bModified     = false;
    tf_v441::Reliability::DeleteRecoverSnapshot(
        tf_v441::Reliability::RecoverPathFor(tab));
    return true;
}

// =============================================================================
//  EXECUTE THREAD
//  Replaced with an inline std::thread in DoExecuteFile; this stub is
//  retained for clarity but is no longer called via _beginthreadex.
// =============================================================================

// =============================================================================
//  SYNTAX CHECK THREAD
//  Modernized: std::thread + ThreadSafeQueue. The thread pushes a
//  unique_ptr<SyntaxCheckResult> into g_SyntaxCheckQueue, then rings the
//  WM_SYNTAX_CHECK_COMPLETE doorbell with a null lParam.
// =============================================================================
static void SyntaxCheckThreadBody(std::unique_ptr<SyntaxCheckParams> params) {
    // v4.11: exit early if shutdown is in progress.
    if (!g_appRunning.load()) {
        g_SyntaxCheckRunning.store(false);
        return;
    }
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hRead = NULL;
    HANDLE hWrite = NULL;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        g_SyntaxCheckRunning.store(false);
        return;
    }
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFO si = { sizeof(si) };
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput  = hWrite;
    si.hStdError   = hWrite;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = { 0 };

    vector<wchar_t> cmdBuffer(params->checkCmd.begin(), params->checkCmd.end());
    cmdBuffer.push_back(0);

    if (CreateProcessW(NULL, cmdBuffer.data(), NULL, NULL, TRUE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hWrite);
        hWrite = NULL;

        string result;
        char   buffer[4096];
        DWORD  bytesRead;
        while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL)
               && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            result += buffer;
        }
        WaitForSingleObject(pi.hProcess, INFINITE);

        auto pResult = std::make_unique<SyntaxCheckResult>();
        pResult->hEdit    = params->hEdit;
        pResult->isPython = params->isPython;
        pResult->isCpp    = params->isCpp;
        pResult->errorLine = -1;

        if (result.empty()) {
            pResult->success = true;
            pResult->output  = L"";
        } else {
            pResult->success = false;
            int wlen = MultiByteToWideChar(CP_UTF8, 0, result.c_str(), -1, NULL, 0);
            vector<wchar_t> wResult(wlen);
            MultiByteToWideChar(CP_UTF8, 0, result.c_str(), -1, wResult.data(), wlen);
            pResult->output = wResult.data();

            if (params->isCpp) {
                size_t errorPos = pResult->output.find(L": error:");
                if (errorPos != wstring::npos && errorPos > 0) {
                    size_t firstCol  = pResult->output.find_last_of(L':', errorPos - 1);
                    if (firstCol != wstring::npos && firstCol > 0) {
                        size_t secondCol = pResult->output.find_last_of(L':', firstCol - 1);
                        if (secondCol != wstring::npos)
                            pResult->errorLine = _wtoi(
                                pResult->output.substr(secondCol + 1,
                                                       firstCol - secondCol - 1).c_str());
                    }
                }
            } else if (params->isPython) {
                size_t lineLabel = pResult->output.find(L"line ");
                if (lineLabel != wstring::npos) {
                    size_t s = lineLabel + 5;
                    size_t e = pResult->output.find_first_not_of(L"0123456789", s);
                    pResult->errorLine = _wtoi(pResult->output.substr(s, e - s).c_str());
                }
            }
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        if (!g_appRunning.load()) {          // v4.11: skip post if shutting down
            if (hRead) CloseHandle(hRead);
            g_SyntaxCheckRunning.store(false);
            return;
        }
        HWND hwnd = params->hwnd;
        g_SyntaxCheckQueue.push(std::move(pResult));
        PostMessage(hwnd, WM_SYNTAX_CHECK_COMPLETE, 0, 0);  // doorbell — lParam null

    } else {
        CloseHandle(hWrite);
        hWrite = NULL;
    }

    if (hRead) CloseHandle(hRead);
    g_SyntaxCheckRunning.store(false);
}

void DoCheckSyntaxAsync(HWND hwnd, HWND hCmdInput) {
    EditorTab* tab = GetActiveTab();
    if (!tab) return;

    // Atomic CAS: expect false (idle), swap to true (running).
    bool expected = false;
    if (!g_SyntaxCheckRunning.compare_exchange_strong(expected, true)) {
        MessageBox(hwnd, L"A syntax check is already running. Please wait.",
                   L"Busy", MB_OK | MB_ICONINFORMATION);
        return;
    }

    tab->errorLine = -1;
    if (tab->bModified || tab->sFilePath.empty()) DoFileSave(hwnd);
    if (tab->sFilePath.empty()) {
        g_SyntaxCheckRunning.store(false);
        return;
    }

    wchar_t cmdBuf[256];
    GetWindowText(hCmdInput, cmdBuf, 256);
    wstring compilerCmd = cmdBuf;
    wstring checkCmd;
    bool isPython = (compilerCmd.find(L"python") != wstring::npos);
    bool isCpp    = (compilerCmd.find(L"g++")    != wstring::npos ||
                     compilerCmd.find(L"gcc")    != wstring::npos);

    if      (isPython) checkCmd = compilerCmd + L" -m py_compile \"" + tab->sFilePath + L"\"";
    else if (isCpp)    checkCmd = compilerCmd + L" -fsyntax-only \"" + tab->sFilePath + L"\"";
    else               checkCmd = compilerCmd + L" \""               + tab->sFilePath + L"\"";

    auto params = std::make_unique<SyntaxCheckParams>();
    params->hwnd     = hwnd;
    params->hEdit    = tab->hEdit;
    params->checkCmd = checkCmd;
    params->isPython = isPython;
    params->isCpp    = isCpp;

    SetWindowTextW(hwnd, L"| Tiny Fantail | Checking Syntax...");

    // v4.11: use tracked thread (no detach).
    g_ThreadMgr.spawn([p = std::move(params)]() mutable {
        SyntaxCheckThreadBody(std::move(p));
    });
}

void HandleSyntaxCheckComplete(HWND hwnd, LPARAM /*lParam*/) {
    // Drain the thread-safe queue; lParam is ignored (it was a doorbell).
    while (true) {
        auto upResult = g_SyntaxCheckQueue.try_pop();
        if (!upResult) break;
        SyntaxCheckResult* pResult = upResult.get();

    EditorTab* tab = NULL;
    for (auto& up : g_Tabs) {
        EditorTab* t = up.get();
        if (t && t->hEdit == pResult->hEdit) { tab = t; break; }
    }

    if (pResult->success) {
        UpdateTitle(hwnd);
        MessageBox(hwnd,
                   L"Check Status: Success\nNo syntax errors detected.",
                   L"Syntax Check", MB_ICONINFORMATION);
    } else {
        wstring report = L"--- ACCURATE SYNTAX DIAGNOSTIC ---\n\n";

        if (pResult->isCpp) {
            size_t errorPos = pResult->output.find(L": error:");
            if (errorPos != wstring::npos) {
                size_t endLine = pResult->output.find(L'\n', errorPos);
                report += L"Fatal " +
                          pResult->output.substr(errorPos + 2, endLine - (errorPos + 2)) + L"\n";
            }
        } else if (pResult->isPython) {
            size_t lastN    = pResult->output.find_last_not_of(L"\r\n ");
            size_t startMsg = pResult->output.find_last_of(L'\n', lastN);
            report += L"PYTHON - " +
                      (startMsg != wstring::npos
                       ? pResult->output.substr(startMsg + 1)
                       : pResult->output) + L"\n";
        }

        if (pResult->errorLine != -1 && tab) {
            tab->errorLine = pResult->errorLine;

            RECT editRect;
            GetClientRect(tab->hEdit, &editRect);
            {
                ScopedDC hdc(tab->hEdit);
                if (hdc.isValid()) {
                    ScopedSelectObject selFont(hdc, hEditorFont);
                    TEXTMETRIC tm;
                    GetTextMetrics(hdc, &tm);
                    int lineH      = tm.tmHeight;
                    int visLines   = editRect.bottom / (lineH > 0 ? lineH : 1);
                    int firstVis   = (int)SendMessage(tab->hEdit, EM_GETFIRSTVISIBLELINE, 0, 0);
                    int targetTop  = (pResult->errorLine - 1) - (visLines / 2);
                    if (targetTop < 0) targetTop = 0;
                    SendMessage(tab->hEdit, EM_LINESCROLL, 0, targetTop - firstVis);
                }
            }

            UpdateGutter(tab->hEdit, tab->hGutter);
            InvalidateRect(tab->hEdit, NULL, TRUE);
            UpdateWindow(tab->hEdit);
            UpdateWindow(tab->hGutter);

            report += L"Line: " + to_wstring(pResult->errorLine) + L"\n";
            report += L"Diagnostic: Visual Centering Synchronized.";
        } else {
            report += L"OUTPUT:\n" + pResult->output;
        }

        UpdateTitle(hwnd);
        MessageBox(hwnd, report.c_str(), L"Accurate Diagnostic", MB_ICONERROR);
    }

    // upResult (unique_ptr) goes out of scope here — automatic cleanup.
    } // end while drain loop
}

void DoExecuteFile(HWND hwnd, HWND hCmdInput) {
    EditorTab* active = GetActiveTab();
    if (!active || active->sFilePath.empty()) {
        MessageBox(hwnd, L"Please save the file first!", L"No Path",
                   MB_OK | MB_ICONWARNING);
        return;
    }

    wchar_t userBuf[1024] = { 0 };
    GetWindowText(hCmdInput, userBuf, 1024);
    std::wstring userCmd(userBuf);
    if (userCmd.empty()) {
        MessageBox(hwnd, L"Terminal command is empty!", L"Error", MB_OK);
        return;
    }

    wchar_t drive[_MAX_DRIVE], dir[_MAX_DIR];
    _wsplitpath_s(active->sFilePath.c_str(), drive, _MAX_DRIVE, dir, _MAX_DIR, NULL, 0, NULL, 0);
    std::wstring workingDir = std::wstring(drive) + std::wstring(dir);

    std::wstring compiler;
    if      (userCmd.find(L"g++")    != std::wstring::npos) compiler = L"g++";
    else if (userCmd.find(L"gcc")    != std::wstring::npos) compiler = L"gcc";
    else if (userCmd.find(L"python") != std::wstring::npos) compiler = L"python";
    else if (userCmd.find(L"py ")    != std::wstring::npos) compiler = L"py";

    std::wstring safePath = active->sFilePath;
    size_t quotePos = 0;
    while ((quotePos = safePath.find(L'"', quotePos)) != std::wstring::npos) {
        safePath.replace(quotePos, 1, L"\\\"");
        quotePos += 2;
    }

    std::wstring coreCommand;
    if (!compiler.empty()) {
        size_t       pos   = userCmd.find(compiler);
        std::wstring part1 = userCmd.substr(0, pos + compiler.length());
        std::wstring part2 = userCmd.substr(pos + compiler.length());
        coreCommand = part1 + L" \"" + safePath + L"\"" + part2;
    } else {
        coreCommand = userCmd;
    }

    std::wstring finalParams = L"/K \"" + coreCommand
        + L" & echo. & set /p dummy=Process finished. Press Enter to exit... & exit\"";

    HINSTANCE result = ShellExecute(NULL, L"open", L"cmd.exe",
                                     finalParams.c_str(), workingDir.c_str(), SW_SHOW);
    if ((INT_PTR)result <= 32)
        MessageBox(hwnd, L"Terminal failed to launch.", L"Error", MB_OK | MB_ICONERROR);
}

// =============================================================================
//  GUTTER PAINT — flicker-free via MemoryDC
// =============================================================================
LRESULT CALLBACK GutterSubclassProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_ERASEBKGND: return 1;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC  hdc = BeginPaint(hWnd, &ps);
        RECT rc;
        GetClientRect(hWnd, &rc);
        int w = rc.right - rc.left;
        int h = rc.bottom - rc.top;

        if (w > 0 && h > 0) {
            MemoryDC memDC(hdc, w, h);
            if (memDC.isValid()) {
                FillRect(memDC, &rc, hGutterBrush);

                EditorTab* gutterTab = (EditorTab*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
                HWND hEdit = gutterTab ? gutterTab->hEdit : NULL;

                if (hEdit) {
                    ScopedSelectObject selFont(memDC, hEditorFont);
                    SetTextColor(memDC, GUTTER_TEXT);
                    SetBkMode(memDC, TRANSPARENT);

                    int first      = (int)SendMessage(hEdit, EM_GETFIRSTVISIBLELINE, 0, 0);
                    int lineCount  = (int)SendMessage(hEdit, EM_GETLINECOUNT, 0, 0);
                    TEXTMETRIC tm;
                    GetTextMetrics(memDC, &tm);
                    int lineH     = (tm.tmHeight > 0) ? tm.tmHeight : 1;
                    int visLines  = (h / lineH) + 1;

                    for (int i = 0; i <= visLines; i++) {
                        int cur = first + i + 1;
                        if (cur <= lineCount) {
                            wchar_t lBuf[16];
                            swprintf_s(lBuf, 16, L"%d ", cur);
                            RECT tr = { 0, i * lineH, w - 5, (i + 1) * lineH };
                            DrawText(memDC, lBuf, -1, &tr,
                                     DT_SINGLELINE | DT_RIGHT | DT_VCENTER);
                        }
                    }
                }
                memDC.blitTo(hdc);
            }
        }
        EndPaint(hWnd, &ps);
        return 0;
    }
    }
    return CallWindowProc(OldGutterProc, hWnd, uMsg, wParam, lParam);
}

// =============================================================================
//  TAB CONTROL PAINT
// =============================================================================
LRESULT CALLBACK TabSubclassProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_ERASEBKGND: return 1;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC  hdc = BeginPaint(hWnd, &ps);
        RECT rc;
        GetClientRect(hWnd, &rc);
        int w = rc.right - rc.left;
        int h = rc.bottom - rc.top;

        if (w > 0 && h > 0) {
            MemoryDC memDC(hdc, w, h);
            if (memDC.isValid()) {
                FillRect(memDC, &rc, hBackBrush);

                int tabCount = TabCtrl_GetItemCount(hWnd);
                int selTab   = TabCtrl_GetCurSel(hWnd);
                ScopedSelectObject selFont(memDC, hUIFont);

                for (int i = 0; i < tabCount; i++) {
                    RECT tabRect;
                    TabCtrl_GetItemRect(hWnd, i, &tabRect);

                    wchar_t szText[MAX_PATH];
                    TCITEM tie;
                    tie.mask       = TCIF_TEXT;
                    tie.pszText    = szText;
                    tie.cchTextMax = MAX_PATH;
                    TabCtrl_GetItem(hWnd, i, &tie);
                    SetBkMode(memDC, TRANSPARENT);

                    if (i == selTab) {
                        FillRect(memDC, &tabRect, GetSysColorBrush(COLOR_BTNFACE));
                        SetTextColor(memDC, RGB(0, 0, 0));
                    } else {
                        FillRect(memDC, &tabRect, GetSysColorBrush(COLOR_BTNSHADOW));
                        SetTextColor(memDC, RGB(255, 255, 255));
                    }

                    RECT textRect  = tabRect;
                    textRect.left += 5;
                    textRect.right -= 25;
                    DrawText(memDC, szText, -1, &textRect,
                             DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_END_ELLIPSIS);

                    RECT closeRect = tabRect;
                    closeRect.left = closeRect.right - 25;
                    DrawText(memDC, L"x", -1, &closeRect,
                             DT_SINGLELINE | DT_VCENTER | DT_CENTER);
                }
                memDC.blitTo(hdc);
            }
        }
        EndPaint(hWnd, &ps);
        return 0;
    }
    }
    return CallWindowProc(OldTabProc, hWnd, uMsg, wParam, lParam);
}

// =============================================================================
//  AUTOFILL: Forward declarations
// =============================================================================
static void HideAutofillPopup();
static void ShowAutofillPopup(HWND hEdit, const std::wstring& prefix);
static std::wstring GetWordBeforeCursor(HWND hEdit);
static void AcceptAutofillSuggestion(HWND hEdit, int listIndex);
static void ShowAutofillManageDialog(HWND hParent);
LRESULT CALLBACK AutofillListSubclassProc(HWND, UINT, WPARAM, LPARAM, UINT_PTR, DWORD_PTR);

static void HideAutofillPopup() {
    if (g_hAutofillPopup && IsWindow(g_hAutofillPopup))
        DestroyWindow(g_hAutofillPopup);
    g_hAutofillPopup   = NULL;
    g_hAutofillListBox = NULL;
    g_hAutofillOwner   = NULL;
}

static std::wstring GetWordBeforeCursor(HWND hEdit) {
    DWORD start = 0, end = 0;
    SendMessage(hEdit, EM_GETSEL, (WPARAM)&start, (LPARAM)&end);
    if (start != end) return L"";

    LRESULT lineIdx   = SendMessage(hEdit, EM_LINEFROMCHAR, start, 0);
    LRESULT lineStart = SendMessage(hEdit, EM_LINEINDEX,    lineIdx, 0);
    int     offsetInLine = (int)(start - lineStart);
    if (offsetInLine <= 0) return L"";

    std::vector<wchar_t> buf(offsetInLine + 2, L'\0');
    *(WORD*)buf.data() = (WORD)(offsetInLine + 1);
    int copied = (int)SendMessage(hEdit, EM_GETLINE, lineIdx, (LPARAM)buf.data());

    int wordEnd   = min(copied, offsetInLine);
    int wordStart = wordEnd;
    while (wordStart > 0 &&
           (iswalnum(buf[wordStart - 1]) || buf[wordStart - 1] == L'_'))
        wordStart--;

    if (wordEnd - wordStart < 2) return L"";
    return std::wstring(buf.data() + wordStart, wordEnd - wordStart);
}

static void AcceptAutofillSuggestion(HWND hEdit, int listIndex) {
    if (!g_hAutofillListBox) return;
    if (listIndex < 0) listIndex = 0;

    int count = (int)SendMessage(g_hAutofillListBox, LB_GETCOUNT, 0, 0);
    if (count == 0 || listIndex >= count) { HideAutofillPopup(); return; }

    int wLen = (int)SendMessage(g_hAutofillListBox, LB_GETTEXTLEN, listIndex, 0);
    if (wLen <= 0) { HideAutofillPopup(); return; }
    std::vector<wchar_t> wordBuf(wLen + 1, L'\0');
    SendMessage(g_hAutofillListBox, LB_GETTEXT, listIndex, (LPARAM)wordBuf.data());
    std::wstring fullWord(wordBuf.data());

    std::wstring prefix = GetWordBeforeCursor(hEdit);
    if (fullWord.length() <= prefix.length()) { HideAutofillPopup(); return; }

    std::wstring toInsert = fullWord.substr(prefix.length()) + L" ";
    ReplaceSelectionWithHistory(hEdit, GetActiveTab(), toInsert);

    DWORD newSel = 0;
    SendMessage(hEdit, EM_GETSEL, (WPARAM)&newSel, 0);
    SendMessage(hEdit, EM_SETSEL, newSel, newSel);
    HideAutofillPopup();
}

LRESULT CALLBACK AutofillListSubclassProc(HWND hWnd, UINT uMsg,
                                           WPARAM wParam, LPARAM lParam,
                                           UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    HWND hEdit = (HWND)(DWORD_PTR)dwRefData;
    switch (uMsg) {
        case WM_KEYDOWN:
            if (wParam == VK_RETURN || wParam == VK_TAB) {
                int sel = (int)SendMessage(hWnd, LB_GETCURSEL, 0, 0);
                if (sel == LB_ERR) sel = 0;
                AcceptAutofillSuggestion(hEdit, sel);
                if (hEdit && IsWindow(hEdit)) SetFocus(hEdit);
                return 0;
            }
            if (wParam == VK_ESCAPE) {
                HideAutofillPopup();
                if (hEdit && IsWindow(hEdit)) SetFocus(hEdit);
                return 0;
            }
            break;
        case WM_CHAR:
            if (wParam == VK_RETURN || wParam == VK_TAB || wParam == VK_ESCAPE)
                return 0;
            HideAutofillPopup();
            if (hEdit && IsWindow(hEdit)) {
                SetFocus(hEdit);
                SendMessage(hEdit, WM_CHAR, wParam, lParam);
            }
            return 0;
        case WM_KILLFOCUS: {
            HWND hNewFocus = (HWND)wParam;
            if (hNewFocus != hEdit &&
                hNewFocus != g_hAutofillPopup &&
                hNewFocus != g_hAutofillListBox)
                HideAutofillPopup();
            break;
        }
        case WM_NCDESTROY:
            RemoveWindowSubclass(hWnd, AutofillListSubclassProc, uIdSubclass);
            break;
    }
    return DefSubclassProc(hWnd, uMsg, wParam, lParam);
}

static POINT GetCaretScreenPos(HWND hEdit) {
    POINT pt = { 0, 0 };

    if (!SendMessage(hEdit, EM_GETCARETPOS, 0, (LPARAM)&pt)) {
        DWORD selEnd = 0;
        SendMessage(hEdit, EM_GETSEL, 0, (LPARAM)&selEnd);

        LRESULT pos = SendMessage(hEdit, EM_POSFROMCHAR, (WPARAM)selEnd, 0);
        if (pos != -1) {
            pt.x = (short)LOWORD(pos);
            pt.y = (short)HIWORD(pos);
        } else if (selEnd > 0) {
            pos = SendMessage(hEdit, EM_POSFROMCHAR, (WPARAM)(selEnd - 1), 0);
            if (pos != -1) {
                ScopedDC hdc(hEdit);
                if (hdc.isValid()) {
                    SIZE sz;
                    HFONT hFont = (HFONT)SendMessage(hEdit, WM_GETFONT, 0, 0);
                    ScopedSelectObject selFont(hdc, hFont);
                    GetTextExtentPoint32(hdc, L" ", 1, &sz);
                    pt.x = (short)LOWORD(pos) + (short)sz.cx;
                    pt.y = (short)HIWORD(pos);
                }
            }
        }
    }

    ClientToScreen(hEdit, &pt);
    return pt;
}

static void ShowAutofillPopup(HWND hEdit, const std::wstring& prefix) {
    std::wstring prefixLower = prefix;
    std::transform(prefixLower.begin(), prefixLower.end(),
                   prefixLower.begin(), ::towlower);

    std::vector<std::wstring> matches;
    for (const auto& w : g_AutofillWords) {
        if (w.length() < prefix.length()) continue;
        std::wstring wLower = w;
        std::transform(wLower.begin(), wLower.end(), wLower.begin(), ::towlower);
        if (wLower.compare(0, prefixLower.length(), prefixLower) == 0)
            matches.push_back(w);
    }
    if (matches.empty()) { HideAutofillPopup(); return; }

    POINT caretPt = GetCaretScreenPos(hEdit);
    UINT  dpi     = GetDpiForHwnd(hEdit);
    int   rowH    = MulDiv(nCurrentFontSize + 8, dpi, 96);
    int   popW    = MulDiv(250, dpi, 96);
    int   visCount = (std::min)((int)matches.size(), 8);
    int   popH    = (rowH * visCount) + 4;

    HMONITOR hMon = MonitorFromPoint(caretPt, MONITOR_DEFAULTTONEAREST);
    MONITORINFO mi = { sizeof(mi) };
    GetMonitorInfo(hMon, &mi);

    int px = caretPt.x;
    int py = caretPt.y + rowH;
    if (py + popH > (int)mi.rcWork.bottom) py = caretPt.y - popH - 2;
    px = (std::max)((int)mi.rcWork.left,
                    (std::min)(px, (int)mi.rcWork.right - popW));

    if (g_hAutofillPopup && IsWindow(g_hAutofillPopup)) {
        SetWindowPos(g_hAutofillPopup, HWND_TOPMOST, px, py, popW, popH,
                     SWP_NOACTIVATE | SWP_SHOWWINDOW);
        SendMessage(g_hAutofillListBox, WM_SETREDRAW, FALSE, 0);
        SendMessage(g_hAutofillListBox, LB_RESETCONTENT, 0, 0);
        for (const auto& m : matches)
            SendMessage(g_hAutofillListBox, LB_ADDSTRING, 0, (LPARAM)m.c_str());
        SendMessage(g_hAutofillListBox, LB_SETCURSEL, 0, 0);
        SendMessage(g_hAutofillListBox, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(g_hAutofillListBox, NULL, TRUE);
    } else {
        g_hAutofillPopup = CreateWindowEx(
            WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_NOACTIVATE,
            L"STATIC", NULL, WS_POPUP | WS_BORDER,
            px, py, popW, popH,
            GetAncestor(hEdit, GA_ROOT), NULL, GetModuleHandle(NULL), NULL);

        g_hAutofillListBox = CreateWindowEx(0, L"LISTBOX", NULL,
            WS_CHILD | WS_VISIBLE | LBS_NOTIFY | LBS_HASSTRINGS |
            LBS_NOINTEGRALHEIGHT | WS_VSCROLL,
            0, 0, popW, popH,
            g_hAutofillPopup, (HMENU)1001, GetModuleHandle(NULL), NULL);

        SendMessage(g_hAutofillListBox, WM_SETFONT, (WPARAM)hEditorFont, TRUE);
        SetWindowSubclass(g_hAutofillListBox, AutofillListSubclassProc, 1, (DWORD_PTR)hEdit);

        for (const auto& m : matches)
            SendMessage(g_hAutofillListBox, LB_ADDSTRING, 0, (LPARAM)m.c_str());
        SendMessage(g_hAutofillListBox, LB_SETCURSEL, 0, 0);

        g_hAutofillOwner = hEdit;
        ShowWindow(g_hAutofillPopup, SW_SHOWNA);
    }
}

static int LoadKeywordsFromFile(const std::wstring& filePath, HWND hListBox) {
    FILE* fp = _wfopen(filePath.c_str(), L"rb");
    if (!fp) return 0;

    fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fileSize <= 0) { fclose(fp); return 0; }

    std::vector<unsigned char> raw((size_t)fileSize + 2, 0);
    size_t bytesRead = fread(raw.data(), 1, (size_t)fileSize, fp);
    fclose(fp);

    if (bytesRead == 0) return 0;

    std::wstring wContent;
    unsigned char* pData  = raw.data();
    size_t         dataLen = bytesRead;

    if (dataLen >= 2 && pData[0] == 0xFF && pData[1] == 0xFE) {
        wContent.assign(reinterpret_cast<wchar_t*>(pData + 2), (dataLen - 2) / 2);
    } else if (dataLen >= 2 && pData[0] == 0xFE && pData[1] == 0xFF) {
        size_t charCount = (dataLen - 2) / 2;
        wContent.resize(charCount);
        for (size_t i = 0; i < charCount; ++i) {
            unsigned char hi = pData[2 + i * 2];
            unsigned char lo = pData[2 + i * 2 + 1];
            wContent[i] = (wchar_t)((hi << 8) | lo);
        }
    } else {
        char*  dataStart = reinterpret_cast<char*>(pData);
        int    convLen   = (int)dataLen;
        if (dataLen >= 3 &&
            (unsigned char)dataStart[0] == 0xEF &&
            (unsigned char)dataStart[1] == 0xBB &&
            (unsigned char)dataStart[2] == 0xBF) {
            dataStart += 3; convLen -= 3;
        }
        if (convLen > 0) {
            int wLen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                           dataStart, convLen, NULL, 0);
            if (wLen > 0) {
                wContent.resize((size_t)wLen);
                MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                    dataStart, convLen, &wContent[0], wLen);
            } else {
                wLen = MultiByteToWideChar(CP_ACP, 0, dataStart, convLen, NULL, 0);
                if (wLen > 0) {
                    wContent.resize((size_t)wLen);
                    MultiByteToWideChar(CP_ACP, 0, dataStart, convLen, &wContent[0], wLen);
                }
            }
        }
    }

    if (wContent.empty()) return 0;

    {
        std::wistringstream scanStream(wContent);
        std::wstring scanLine;
        int lineNum = 0;
        while (std::getline(scanStream, scanLine)) {
            ++lineNum;
            if (!scanLine.empty() && scanLine.back() == L'\r') scanLine.pop_back();
            size_t first = scanLine.find_first_not_of(L" \t\xFEFF");
            if (first == std::wstring::npos) continue;
            size_t last = scanLine.find_last_not_of(L" \t\r");
            std::wstring trimmed = scanLine.substr(first, last - first + 1);
            if (trimmed.find_first_of(L" \t") != std::wstring::npos)
                return -(lineNum);
        }
    }

    std::unordered_set<std::wstring> existingLower;
    existingLower.reserve(g_AutofillWords.size());
    for (const auto& w : g_AutofillWords) {
        std::wstring wl = w;
        for (auto& c : wl) c = towlower(c);
        existingLower.insert(std::move(wl));
    }

    int addedCount = 0;
    std::wistringstream stream(wContent);
    std::wstring line;

    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == L'\r') line.pop_back();
        size_t first = line.find_first_not_of(L" \t\xFEFF");
        if (first == std::wstring::npos) continue;
        size_t last = line.find_last_not_of(L" \t\r");
        if (last == std::wstring::npos) continue;
        std::wstring word = line.substr(first, last - first + 1);
        if (word.empty()) continue;

        std::wstring wordLower = word;
        for (auto& c : wordLower) c = towlower(c);

        if (existingLower.find(wordLower) == existingLower.end()) {
            existingLower.insert(wordLower);
            g_AutofillWords.push_back(word);
            if (hListBox && IsWindow(hListBox))
                SendMessage(hListBox, LB_ADDSTRING, 0, (LPARAM)word.c_str());
            addedCount++;
        }
    }

    return addedCount;
}

// =============================================================================
//  AUTOFILL: Manage dialog proc
// =============================================================================
static INT_PTR CALLBACK AutofillDlgProc(HWND hDlg, UINT uMsg,
                                          WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_INITDIALOG: {
            HWND hList = GetDlgItem(hDlg, IDC_AUTOFILL_LIST);
            SendMessage(hList, LB_RESETCONTENT, 0, 0);
            for (const auto& w : g_AutofillWords)
                SendMessage(hList, LB_ADDSTRING, 0, (LPARAM)w.c_str());
            return TRUE;
        }
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDC_AUTOFILL_ADD: {
                    HWND hInput = GetDlgItem(hDlg, IDC_AUTOFILL_INPUT);
                    HWND hList  = GetDlgItem(hDlg, IDC_AUTOFILL_LIST);
                    int  len    = GetWindowTextLength(hInput);
                    if (len <= 0) break;
                    std::wstring word(len + 1, L'\0');
                    GetWindowText(hInput, &word[0], len + 1);
                    word.resize(len);
                    while (!word.empty() && iswspace(word.front())) word.erase(word.begin());
                    while (!word.empty() && iswspace(word.back()))  word.pop_back();
                    if (word.empty()) break;

                    std::wstring wordLower = word;
                    for (auto& c : wordLower) c = towlower(c);
                    bool exists = false;
                    for (const auto& w : g_AutofillWords) {
                        std::wstring wl = w;
                        for (auto& c : wl) c = towlower(c);
                        if (wl == wordLower) { exists = true; break; }
                    }
                    if (!exists) {
                        g_AutofillWords.push_back(word);
                        SendMessage(hList, LB_ADDSTRING, 0, (LPARAM)word.c_str());
                    }
                    SetWindowText(hInput, L"");
                    SetFocus(hInput);
                    break;
                }
                case IDC_AUTOFILL_DEL: {
                    HWND hList = GetDlgItem(hDlg, IDC_AUTOFILL_LIST);
                    int  sel   = (int)SendMessage(hList, LB_GETCURSEL, 0, 0);
                    if (sel == LB_ERR) break;
                    int  delLen = (int)SendMessage(hList, LB_GETTEXTLEN, sel, 0);
                    std::vector<wchar_t> delBuf(delLen + 1, L'\0');
                    SendMessage(hList, LB_GETTEXT, sel, (LPARAM)delBuf.data());
                    std::wstring toRemove(delBuf.data());
                    g_AutofillWords.erase(
                        std::remove(g_AutofillWords.begin(), g_AutofillWords.end(), toRemove),
                        g_AutofillWords.end());
                    SendMessage(hList, LB_DELETESTRING, sel, 0);
                    break;
                }
                case IDC_AUTOFILL_LOAD_FILE: {
                    wchar_t szFile[MAX_PATH] = { 0 };
                    OPENFILENAMEW ofn = { 0 };
                    ofn.lStructSize  = sizeof(ofn);
                    ofn.hwndOwner    = hDlg;
                    ofn.lpstrFile    = szFile;
                    ofn.nMaxFile     = MAX_PATH;
                    ofn.lpstrFilter  = L"Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
                    ofn.nFilterIndex = 1;
                    ofn.lpstrTitle   = L"Load Keywords File";
                    ofn.Flags        = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;

                    if (GetOpenFileNameW(&ofn)) {
                        HWND hList  = GetDlgItem(hDlg, IDC_AUTOFILL_LIST);
                        int  result = LoadKeywordsFromFile(szFile, hList);

                        if (result < 0) {
                            wchar_t errBuf[256];
                            swprintf_s(errBuf, 256,
                                L"Load rejected: line %d contains more than one word.\n\n"
                                L"Each line must contain exactly one keyword.",
                                -(result));
                            MessageBoxW(hDlg, errBuf, L"Invalid File Format",
                                        MB_OK | MB_ICONERROR);
                        } else if (result > 0) {
                            wchar_t msgBuf[128];
                            swprintf_s(msgBuf, 128,
                                       L"%d keyword(s) loaded successfully.", result);
                            MessageBoxW(hDlg, msgBuf, L"Keywords Loaded",
                                        MB_OK | MB_ICONINFORMATION);
                        } else {
                            MessageBoxW(hDlg,
                                L"No new keywords were added.\n"
                                L"The file may be empty, or all keywords already exist.",
                                L"Nothing Added", MB_OK | MB_ICONWARNING);
                        }
                    }
                    break;
                }
                case IDC_AUTOFILL_CLEAR_ALL: {
                    int choice = MessageBoxW(hDlg,
                        L"Are you sure you want to clear ALL keywords?\n"
                        L"This action cannot be undone.",
                        L"Clear All Keywords",
                        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2);
                    if (choice == IDYES) {
                        { std::vector<std::wstring> empty; empty.swap(g_AutofillWords); }
                        HeapCompact(GetProcessHeap(), 0);
                        HWND hList = GetDlgItem(hDlg, IDC_AUTOFILL_LIST);
                        if (hList) SendMessage(hList, LB_RESETCONTENT, 0, 0);
                    }
                    break;
                }
                case IDOK:
                case IDCANCEL:
                    EndDialog(hDlg, 0);
                    return TRUE;
            }
            break;
        }
        case WM_KEYDOWN:
            if (wParam == VK_ESCAPE) { EndDialog(hDlg, 0); return TRUE; }
            break;
    }
    return FALSE;
}

// =============================================================================
//  AUTOFILL: Manage dialog — built from in-memory template
// =============================================================================
static void ShowAutofillManageDialog(HWND hParent) {
    const DWORD bufSize = 8192;
    std::vector<BYTE> tpl(bufSize, 0);
    BYTE* p    = tpl.data();
    BYTE* pEnd = tpl.data() + bufSize;
    bool tplOk = true;

    auto remaining = [&]() -> size_t { return (p <= pEnd) ? (size_t)(pEnd - p) : 0; };
    auto writeBytes = [&](const void* src, size_t bytes) {
        if (!tplOk || bytes > remaining()) { tplOk = false; return; }
        memcpy(p, src, bytes);
        p += bytes;
    };
    auto writeW   = [&](WORD  w) { writeBytes(&w, sizeof(w)); };
    auto writeDW  = [&](DWORD d) { writeBytes(&d, sizeof(d)); };
    auto writeStr = [&](const wchar_t* s) {
        size_t n = wcslen(s) + 1;
        if (n > (std::numeric_limits<size_t>::max() / sizeof(wchar_t))) {
            tplOk = false;
            return;
        }
        writeBytes(s, n * sizeof(wchar_t));
    };
    auto align4 = [&]() {
        while (tplOk && ((p - tpl.data()) % 4) != 0) {
            BYTE zero = 0;
            writeBytes(&zero, sizeof(zero));
        }
    };

    writeW(1); writeW(0xFFFF);
    writeDW(0);
    writeDW(WS_EX_DLGMODALFRAME | DS_SETFONT | DS_CENTER);
    writeDW(WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME | DS_SETFONT | DS_CENTER | WS_VISIBLE);
    writeW(8); writeW(0); writeW(0); writeW(260); writeW(180);
    writeW(0); writeW(0);
    writeStr(L"Manage Autofill Words");
    writeW(9); writeW(FW_NORMAL);
    if (p < pEnd) *p++ = 0;
    if (p < pEnd) *p++ = DEFAULT_CHARSET;
    writeStr(L"Segoe UI");

    auto writeItem = [&](DWORD exStyle, DWORD style, short x, short y, short cx, short cy,
                         DWORD id, const wchar_t* cls, const wchar_t* txt) {
        align4();
        writeDW(0); writeDW(exStyle); writeDW(style);
        writeW((WORD)x); writeW((WORD)y); writeW((WORD)cx); writeW((WORD)cy);
        writeDW(id);
        writeStr(cls); writeStr(txt); writeW(0);
    };

    writeItem(0, WS_VISIBLE|WS_CHILD|SS_LEFT,
              7, 8, 45, 12, 0xFFFF, L"STATIC", L"Add Word:");
    writeItem(WS_EX_CLIENTEDGE, WS_VISIBLE|WS_CHILD|WS_BORDER|ES_AUTOHSCROLL,
              55, 6, 130, 14, IDC_AUTOFILL_INPUT, L"EDIT", L"");
    writeItem(0, WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON|WS_TABSTOP,
              190, 6, 60, 14, IDC_AUTOFILL_ADD, L"BUTTON", L"Add");
    writeItem(WS_EX_CLIENTEDGE, WS_VISIBLE|WS_CHILD|WS_VSCROLL|WS_BORDER|LBS_NOTIFY|LBS_HASSTRINGS,
              7, 26, 243, 118, IDC_AUTOFILL_LIST, L"LISTBOX", L"");
    writeItem(0, WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON|WS_TABSTOP,
               7, 152, 60, 18, IDC_AUTOFILL_DEL,       L"BUTTON", L"Delete");
    writeItem(0, WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON|WS_TABSTOP,
              69, 152, 60, 18, IDC_AUTOFILL_LOAD_FILE,  L"BUTTON", L"Load File...");
    writeItem(0, WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON|WS_TABSTOP,
             131, 152, 60, 18, IDC_AUTOFILL_CLEAR_ALL,  L"BUTTON", L"Clear All");
    writeItem(0, WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON|WS_TABSTOP|BS_DEFPUSHBUTTON,
             193, 152, 60, 18, IDOK,                    L"BUTTON", L"Close");

    if (!tplOk) {
        MessageBoxW(hParent, L"Autofill dialog template overflow was prevented.",
                    L"Autofill", MB_OK | MB_ICONERROR);
        return;
    }

    DialogBoxIndirectW(GetModuleHandle(NULL), (LPDLGTEMPLATE)tpl.data(),
                       hParent, AutofillDlgProc);
}

// =============================================================================
//  MAIN EDITOR SUBCLASS PROCEDURE
//  Piece Table integration:
//    • WM_CHAR / WM_KEYDOWN: after CommitEditCommand the PT is already updated
//      via ApplyPieceTableEdit (called inside CommitEditCommand).
//    • WM_PAINT: reads cachedDoc which is rebuilt from pt.GetVirtualText()
//      whenever cachedDocDirty is set.
//    • EN_CHANGE (in WindowProc): sets tab->ptDirty = true for edits that
//      bypass our tracked path (e.g. WM_SETTEXT from clipboard manager).
// =============================================================================
LRESULT CALLBACK EditSubclassProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    static vector<wchar_t> lineBuf;
    const  UINT_PTR MESSAGE_TIMER_ID = 999;

    EditorTab* tab = (EditorTab*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    if (!tab) return CallWindowProc(OldEditProc, hWnd, uMsg, wParam, lParam);

    HWND hGutter  = tab->hGutter;
    HWND hMainWnd = GetParent(hWnd);

    auto RefreshAllIndicators = [&](HWND hE) {
        UpdateColInfo(hE);
        UpdateLineCount(hE, hGlobalLineCount);
        UpdateCharacterCount(hE, hCharLabel);
        UpdateWordCount(hE, hWordCount);
    };

    // v4.33: 16 ms (~60 Hz) coalescing timer for scroll/wheel-driven repaints.
    // Mouse-wheel bursts and scrollbar drags fire dozens of WM_VSCROLL /
    // WM_MOUSEWHEEL per second; previously each one synchronously invalidated
    // the gutter AND the entire edit client area, doubling paint cost. We now
    // collapse them into one paint per frame via a one-shot timer.
    const UINT_PTR SCROLL_REPAINT_TIMER_ID = 0xE1C1;

    switch (uMsg) {
    case WM_TIMER: {
        if (wParam == MESSAGE_TIMER_ID) {
            KillTimer(hWnd, MESSAGE_TIMER_ID);
            UpdateTitle(hMainWnd);
            break;
        }
        if (wParam == SCROLL_REPAINT_TIMER_ID) {
            KillTimer(hWnd, SCROLL_REPAINT_TIMER_ID);
            // Caret position is unchanged by pure scroll, so we skip the
            // four Update* indicator calls — only the gutter and the edit
            // client need to repaint to reflect the new visible window.
            if (hGutter && IsWindow(hGutter))
                InvalidateRect(hGutter, NULL, FALSE);
            InvalidateRect(hWnd, NULL, FALSE);
            break;
        }
        break;
    }

    case WM_KEYDOWN: {
        bool ctrl  = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
        bool shift = (GetKeyState(VK_SHIFT)   & 0x8000) != 0;

        if (g_hAutofillPopup && IsWindow(g_hAutofillPopup) &&
            g_hAutofillOwner == hWnd) {
            if (wParam == VK_DOWN) {
                if (g_hAutofillListBox) {
                    int cur   = (int)SendMessage(g_hAutofillListBox, LB_GETCURSEL, 0, 0);
                    int total = (int)SendMessage(g_hAutofillListBox, LB_GETCOUNT,  0, 0);
                    if (cur == LB_ERR) cur = 0;
                    else cur = (cur + 1 < total) ? cur + 1 : cur;
                    SendMessage(g_hAutofillListBox, LB_SETCURSEL, cur, 0);
                }
                return 0;
            }
            if (wParam == VK_UP) {
                if (g_hAutofillListBox) {
                    int cur = (int)SendMessage(g_hAutofillListBox, LB_GETCURSEL, 0, 0);
                    if (cur == LB_ERR) cur = 0;
                    else cur = (cur - 1 >= 0) ? cur - 1 : 0;
                    SendMessage(g_hAutofillListBox, LB_SETCURSEL, cur, 0);
                }
                return 0;
            }
            if (wParam == VK_RETURN || wParam == VK_TAB) {
                g_bAutofillAcceptPending = true;
                int sel = g_hAutofillListBox
                          ? (int)SendMessage(g_hAutofillListBox, LB_GETCURSEL, 0, 0)
                          : 0;
                if (sel == LB_ERR) sel = 0;
                AcceptAutofillSuggestion(hWnd, sel);
                return 0;
            }
            if (wParam == VK_ESCAPE) { HideAutofillPopup(); return 0; }
            if (wParam == VK_LEFT || wParam == VK_RIGHT || wParam == VK_HOME ||
                wParam == VK_END  || wParam == VK_PRIOR || wParam == VK_NEXT)
                HideAutofillPopup();
        }

        if (wParam == VK_BACK || wParam == VK_DELETE ||
            (ctrl && wParam == 'X')) {
            DWORD start, end;
            SendMessage(hWnd, EM_GETSEL, (WPARAM)&start, (LPARAM)&end);
            int textLen = GetWindowTextLength(hWnd);

            if (start == 0 && end >= (DWORD)textLen && textLen > 100) {
                int choice = MessageBox(hWnd,
                    L"Clear history and purge RAM?",
                    L"Memory Guard", MB_YESNOCANCEL | MB_ICONQUESTION);
                if (choice == IDYES) {
                    ClearTabRamPayload(tab, false, true);
                    tab->bModified = true;
                    TrimProcessRamNow();
                    // v4.34: full purge — model just changed massively, take
                    // the slow path immediately rather than coalescing.
                    RefreshAllIndicators(hWnd);
                    if (hGutter) UpdateGutter(hWnd, hGutter);
                    return 0;
                } else if (choice == IDCANCEL) {
                    return 0;
                }
            }

            EditCommand deleteCommand;
            bool hasDeleteCommand = false;
            if (start != end) {
                deleteCommand    = BeginReplaceCommand(hWnd, start, end, L"", start, end);
                hasDeleteCommand = !deleteCommand.removedText.empty();
            } else if (wParam == VK_BACK && start > 0) {
                deleteCommand    = BeginReplaceCommand(hWnd, start - 1, start, L"", start, end);
                hasDeleteCommand = !deleteCommand.removedText.empty();
            } else if (wParam == VK_DELETE && start < (DWORD)textLen) {
                deleteCommand    = BeginReplaceCommand(hWnd, start, start + 1, L"", start, end);
                hasDeleteCommand = !deleteCommand.removedText.empty();
            }

            LRESULT res = CallWindowProc(OldEditProc, hWnd, uMsg, wParam, lParam);

            if (hasDeleteCommand)
                CommitEditCommand(tab, deleteCommand, false);

            if (start != end) {
                int lineStart = (int)SendMessage(hWnd, EM_LINEFROMCHAR, start, 0);
                int lineEnd   = (int)SendMessage(hWnd, EM_LINEFROMCHAR, end,   0);
                if (lineEnd >= lineStart) {
                    wchar_t msg[128];
                    swprintf(msg, 128,
                             L"Deleting range: Lines %d to %d",
                             lineStart + 1, lineEnd + 1);
                    SetWindowText(hMainWnd, msg);
                    SetTimer(hWnd, MESSAGE_TIMER_ID, 3000, NULL);
                    SetProp(hWnd, L"FlashLine",  (HANDLE)(DWORD_PTR)lineStart);
                    SetProp(hWnd, L"FlashEnd",   (HANDLE)(DWORD_PTR)lineEnd);
                    SetProp(hWnd, L"FlashTimer", (HANDLE)8);
                    SetProp(hWnd, L"FlashColor", (HANDLE)(DWORD_PTR)RGB(255, 80, 80));
                }
                tab->bModified = true;
                // v4.34: coalesce the heavy readouts; col indicator updates
                // immediately so the status bar caret column stays live.
                UpdateColInfo(hWnd);
                RequestEditUiRefresh(hMainWnd);
            }
            return res;
        }

        if (ctrl && (wParam == VK_UP || wParam == VK_DOWN)) {
            DWORD curTime = GetTickCount();
            if (curTime - tab->lastPressTime < 500) {
                if (tab->skipMultiplier < 10) tab->skipMultiplier++;
            } else { tab->skipMultiplier = 1; }
            tab->lastPressTime = curTime;

            DWORD start;
            SendMessage(hWnd, EM_GETSEL, (WPARAM)&start, 0);
            int curLine  = (int)SendMessage(hWnd, EM_LINEFROMCHAR, start, 0);
            int total    = (int)SendMessage(hWnd, EM_GETLINECOUNT, 0, 0);
            int jumpSize = tab->skipMultiplier * 2;
            int targetLine = (wParam == VK_UP) ? (curLine - jumpSize) : (curLine + jumpSize);
            targetLine = max(0, min(targetLine, total - 1));

            SetProp(hWnd, L"HighlightLine",  (HANDLE)(DWORD_PTR)targetLine);
            SetProp(hWnd, L"HighlightTimer", (HANDLE)10);

            int idx = (int)SendMessage(hWnd, EM_LINEINDEX, targetLine, 0);
            SendMessage(hWnd, EM_SETSEL, idx, idx);
            SendMessage(hWnd, EM_SCROLLCARET, 0, 0);
            // v4.34: caret move only — do the cheap col update inline,
            // coalesce the heavy line/char/word readouts.
            UpdateColInfo(hWnd);
            RequestEditUiRefresh(hMainWnd);
            return 0;
        }

        if (ctrl) {
            if (wParam == VK_BACK) {
                DWORD start, end;
                SendMessage(hWnd, EM_GETSEL, (WPARAM)&start, (LPARAM)&end);
                if (start == end && start >= 4) {
                    int lineIdx    = (int)SendMessage(hWnd, EM_LINEFROMCHAR, start, 0);
                    int lineStart  = (int)SendMessage(hWnd, EM_LINEINDEX, lineIdx, 0);
                    int charInLine = (int)start - lineStart;
                    if (charInLine >= 4) {
                        int lineLen = (int)SendMessage(hWnd, EM_LINELENGTH,
                                                       (WPARAM)lineStart, 0);
                        std::vector<wchar_t> fBuf(lineLen + 2, L'\0');
                        *(WORD*)fBuf.data() = (WORD)(lineLen + 1);
                        SendMessage(hWnd, EM_GETLINE, lineIdx, (LPARAM)fBuf.data());
                        bool isSpaces = true;
                        for (int i = 1; i <= 4; i++)
                            if (fBuf[charInLine - i] != L' ') { isSpaces = false; break; }
                        if (isSpaces) {
                            SendMessage(hWnd, EM_SETSEL, (WPARAM)(start - 4), (LPARAM)start);
                            ReplaceSelectionWithHistory(hWnd, tab, L"");
                            tab->bModified = true;
                            UpdateColInfo(hWnd);
                            RequestEditUiRefresh(hMainWnd);
                            return 0;
                        }
                    }
                }
            }

            if (wParam == VK_OEM_PLUS  || wParam == VK_ADD)
                { UpdateEditorFont(hWnd, hGutter, nCurrentFontSize + 2); return 0; }
            if (wParam == VK_OEM_MINUS || wParam == VK_SUBTRACT)
                { UpdateEditorFont(hWnd, hGutter, nCurrentFontSize - 2); return 0; }
            if (wParam == '0')
                { UpdateEditorFont(hWnd, hGutter, 24); return 0; }

            if (wParam == 'Z' && !shift) {
                if (!tab->undoStack.empty()) {
                    DWORD flashIndex = tab->undoStack.back().index;
                    int linesBefore  = (int)SendMessage(hWnd, EM_GETLINECOUNT, 0, 0);
                    UndoEditCommand(tab);
                    // v4.34: undo can land on a huge buffer mutation — the
                    // 16 ms coalescer handles line/word/char counts, gutter,
                    // and stats together in the next tick.
                    UpdateColInfo(hWnd);
                    RequestEditUiRefresh(hMainWnd);

                    int lineStart = max(0, (int)SendMessage(hWnd, EM_LINEFROMCHAR,
                                                            flashIndex, 0));
                    int linesAfter = (int)SendMessage(hWnd, EM_GETLINECOUNT, 0, 0);
                    int lineEnd    = lineStart + max(0, abs(linesAfter - linesBefore));

                    wchar_t undoMsg[128];
                    swprintf(undoMsg, 128,
                             L"Undo: Delta Lines %d to %d", lineStart + 1, lineEnd + 1);
                    SetWindowText(hMainWnd, undoMsg);
                    SetTimer(hWnd, MESSAGE_TIMER_ID, 3000, NULL);
                    SetProp(hWnd, L"FlashLine",  (HANDLE)(DWORD_PTR)lineStart);
                    SetProp(hWnd, L"FlashEnd",   (HANDLE)(DWORD_PTR)lineEnd);
                    SetProp(hWnd, L"FlashTimer", (HANDLE)12);
                    SetProp(hWnd, L"FlashColor", (HANDLE)(DWORD_PTR)RGB(255, 200, 0));

                    // v4.34: gutter repaint folded into the EN_CHANGE coalescer.
                    UpdateTitle(hMainWnd);
                    return 0;
                }
                return 0;
            }

            if (wParam == 'Y' || (wParam == 'Z' && shift)) {
                if (!tab->redoStack.empty()) {
                    DWORD flashIndex = tab->redoStack.back().index;
                    int linesBefore  = (int)SendMessage(hWnd, EM_GETLINECOUNT, 0, 0);
                    RedoEditCommand(tab);
                    UpdateColInfo(hWnd);
                    RequestEditUiRefresh(hMainWnd);

                    int lineStart = max(0, (int)SendMessage(hWnd, EM_LINEFROMCHAR,
                                                            flashIndex, 0));
                    int linesAfter = (int)SendMessage(hWnd, EM_GETLINECOUNT, 0, 0);
                    int lineEnd    = lineStart + max(0, abs(linesAfter - linesBefore));

                    wchar_t redoMsg[128];
                    swprintf(redoMsg, 128,
                             L"Redo: Delta Lines %d to %d", lineStart + 1, lineEnd + 1);
                    SetWindowText(hMainWnd, redoMsg);
                    SetTimer(hWnd, MESSAGE_TIMER_ID, 3000, NULL);
                    SetProp(hWnd, L"FlashLine",  (HANDLE)(DWORD_PTR)lineStart);
                    SetProp(hWnd, L"FlashEnd",   (HANDLE)(DWORD_PTR)lineEnd);
                    SetProp(hWnd, L"FlashTimer", (HANDLE)12);
                    SetProp(hWnd, L"FlashColor", (HANDLE)(DWORD_PTR)RGB(0, 180, 255));

                    // v4.34: gutter repaint folded into the EN_CHANGE coalescer.
                    UpdateTitle(hMainWnd);
                    return 0;
                }
                return 0;
            }
        }
        break;
    }

    case WM_CHAR: {
        if (g_bAutofillAcceptPending &&
            (wParam == VK_RETURN || wParam == VK_TAB)) {
            g_bAutofillAcceptPending = false;
            return 0;
        }
        g_bAutofillAcceptPending = false;

        if (wParam == VK_BACK && g_hAutofillOwner == hWnd)
            HideAutofillPopup();

        if (wParam == 0x7F) return 0;
        if (wParam == 1)  { SendMessage(hWnd, EM_SETSEL, 0, -1); return 0; }

        if (!tab->isRestoring && wParam >= 32)
            { tab->bModified = true; UpdateTitle(hMainWnd); }

        if (wParam == VK_TAB) {
            ReplaceSelectionWithHistory(hWnd, tab, L"    ");
            // v4.34: coalesce; col is unchanged enough that we skip even UpdateColInfo.
            RequestEditUiRefresh(hMainWnd);
            return 0;
        }

        wchar_t ch        = (wchar_t)wParam;
        wchar_t closePair = 0;

        if      (ch == L'{')  closePair = L'}';
        else if (ch == L'[')  closePair = L']';
        else if (ch == L'(')  closePair = L')';
        else if (ch == L'\"') closePair = L'\"';
        else if (ch == L'\'') closePair = L'\'';

        if (ch == L'}' || ch == L']' || ch == L')' ||
            ch == L'\"' || ch == L'\'') {
            DWORD start, end;
            SendMessage(hWnd, EM_GETSEL, (WPARAM)&start, (LPARAM)&end);

            LRESULT lineIdx   = SendMessage(hWnd, EM_LINEFROMCHAR, start, 0);
            LRESULT lineStart = SendMessage(hWnd, EM_LINEINDEX, lineIdx, 0);
            size_t  offsetInLine = start - lineStart;

            std::vector<wchar_t> peekBuf(offsetInLine + 2, L'\0');
            *(WORD*)peekBuf.data() = (WORD)(offsetInLine + 1);
            if (SendMessage(hWnd, EM_GETLINE, lineIdx, (LPARAM)peekBuf.data())
                    > (LRESULT)offsetInLine) {
                wchar_t nextChar = peekBuf[offsetInLine];
                if (nextChar == ch) {
                    SendMessage(hWnd, EM_SETSEL, start + 1, start + 1);
                    return 0;
                }
            }
        }

        if (closePair != 0) {
            DWORD pairStart = 0, pairEnd = 0;
            SendMessage(hWnd, EM_GETSEL, (WPARAM)&pairStart, (LPARAM)&pairEnd);
            std::wstring pairStr;
            pairStr += ch;
            pairStr += closePair;
            EditCommand pairCommand = BeginReplaceCommand(hWnd, pairStart, pairEnd,
                                                          pairStr, pairStart, pairEnd);
            SendMessage(hWnd, EM_REPLACESEL, TRUE, (LPARAM)pairStr.c_str());
            DWORD start;
            SendMessage(hWnd, EM_GETSEL, (WPARAM)&start, 0);
            SendMessage(hWnd, EM_SETSEL, start - 1, start - 1);
            CommitEditCommand(tab, pairCommand, false);
            tab->bModified = true;
            UpdateTitle(hMainWnd);
            // v4.34: bracket pair insert — caret moved by 1, coalesce heavy work.
            UpdateColInfo(hWnd);
            RequestEditUiRefresh(hMainWnd);
            return 0;
        }

        if (wParam == VK_RETURN) {
            const std::wstring newline = L"\r\n";
            DWORD start = 0, end = 0;
            SendMessage(hWnd, EM_GETSEL, (WPARAM)&start, (LPARAM)&end);

            LRESULT totalLen = SendMessage(hWnd, WM_GETTEXTLENGTH, 0, 0);
            if (start > static_cast<DWORD>(totalLen)) start = (DWORD)totalLen;

            auto finalizeReturn = [&]() {
                SendMessage(hWnd, EM_SCROLLCARET, 0, 0);
                tab->bModified = true;
                UpdateTitle(hMainWnd);
                // v4.34: Enter handler — line count actually changed, but the
                // 16 ms coalescer still bundles the line/word/char/gutter
                // pass with any further keystrokes the user fires off in
                // the same burst (auto-indent then immediate typing).
                UpdateColInfo(hWnd);
                RequestEditUiRefresh(hMainWnd);
            };

            LRESULT lineIndex = SendMessage(hWnd, EM_LINEFROMCHAR, start, 0);
            if (lineIndex >= 0) {
                LRESULT lineStart  = SendMessage(hWnd, EM_LINEINDEX, lineIndex, 0);
                LRESULT lineLength = SendMessage(hWnd, EM_LINELENGTH, lineStart, 0);

                if (lineLength >= 0) {
                    std::vector<wchar_t> buffer(lineLength + 1, L'\0');
                    *(WORD*)buffer.data() = (WORD)lineLength;
                    LRESULT copied = SendMessage(hWnd, EM_GETLINE,
                                                 lineIndex, (LPARAM)buffer.data());
                    std::wstring lineText(buffer.data(),
                                          (copied > 0) ? (size_t)copied : 0);

                    std::wstring baseIndent;
                    bool usesTabs = false;
                    for (wchar_t c : lineText) {
                        if      (c == L' ')  baseIndent += c;
                        else if (c == L'\t') { baseIndent += c; usesTabs = true; }
                        else break;
                    }

                    std::wstring indentUnit  = usesTabs ? L"\t" : L"    ";
                    size_t       cursorInLine = (size_t)(start - lineStart);

                    bool isBetweenBrackets = false;
                    if (cursorInLine > 0 && cursorInLine < lineText.length()) {
                        wchar_t cb = lineText[cursorInLine - 1];
                        wchar_t ca = lineText[cursorInLine];
                        if ((cb == L'{' && ca == L'}') ||
                            (cb == L'[' && ca == L']') ||
                            (cb == L'(' && ca == L')'))
                            isBetweenBrackets = true;
                    }

                    if (isBetweenBrackets) {
                        std::wstring smartInsert =
                            newline + baseIndent + indentUnit + newline + baseIndent;
                        EditCommand enterCommand = BeginReplaceCommand(
                            hWnd, start, end, smartInsert, start, end);
                        SendMessage(hWnd, EM_REPLACESEL, TRUE, (LPARAM)smartInsert.c_str());
                        DWORD newCaretPos = start + (DWORD)(
                            newline.length() + baseIndent.length() + indentUnit.length());
                        SendMessage(hWnd, EM_SETSEL, newCaretPos, newCaretPos);
                        CommitEditCommand(tab, enterCommand, false);
                        finalizeReturn();
                        return 0;
                    }

                    std::wstring beforeCursor = lineText.substr(0, cursorInLine);
                    size_t lastNonWS = beforeCursor.find_last_not_of(L" \t\r\n");
                    if (lastNonWS != std::wstring::npos) {
                        wchar_t trigger = beforeCursor[lastNonWS];
                        if (trigger == L'{' || trigger == L'[' || trigger == L':') {
                            std::wstring simpleIndent = newline + baseIndent + indentUnit;
                            EditCommand enterCommand = BeginReplaceCommand(
                                hWnd, start, end, simpleIndent, start, end);
                            SendMessage(hWnd, EM_REPLACESEL, TRUE, (LPARAM)simpleIndent.c_str());
                            CommitEditCommand(tab, enterCommand, false);
                            finalizeReturn();
                            return 0;
                        }
                    }

                    std::wstring standardIndent = newline + baseIndent;
                    EditCommand enterCommand = BeginReplaceCommand(
                        hWnd, start, end, standardIndent, start, end);
                    SendMessage(hWnd, EM_REPLACESEL, TRUE, (LPARAM)standardIndent.c_str());
                    CommitEditCommand(tab, enterCommand, false);
                    finalizeReturn();
                    return 0;
                }
            }

            EditCommand enterCommand = BeginReplaceCommand(hWnd, start, end, newline, start, end);
            SendMessage(hWnd, EM_REPLACESEL, TRUE, (LPARAM)newline.c_str());
            CommitEditCommand(tab, enterCommand, false);
            finalizeReturn();
            return 0;
        }

        {
            EditCommand typeCommand;
            bool trackTyping = !tab->isRestoring && wParam >= 32;
            if (trackTyping) {
                DWORD typeStart = 0, typeEnd = 0;
                SendMessage(hWnd, EM_GETSEL, (WPARAM)&typeStart, (LPARAM)&typeEnd);
                typeCommand = BeginReplaceCommand(hWnd, typeStart, typeEnd,
                    std::wstring(1, (wchar_t)wParam), typeStart, typeEnd);
            }
            LRESULT defaultResult = CallWindowProc(OldEditProc, hWnd, uMsg, wParam, lParam);
            if (trackTyping)
                CommitEditCommand(tab, typeCommand,
                    typeCommand.removedText.empty() &&
                    typeCommand.insertedText.length() == 1);

            if (!tab->isRestoring && wParam >= 32 && !g_AutofillWords.empty()) {
                std::wstring prefix = GetWordBeforeCursor(hWnd);
                if (!prefix.empty()) ShowAutofillPopup(hWnd, prefix);
                else HideAutofillPopup();
            }
            // v4.34 — the per-keystroke hot path. UpdateColInfo is cheap
            // (one EM_GETSEL + EM_LINEFROMCHAR + EM_LINEINDEX + a 2-int
            // formatted SetWindowText) and the user expects the column
            // indicator to track every keystroke. Everything else —
            // line count, char count, word count, gutter repaint, piece
            // count, deferred-stats worker — is folded into the 16 ms
            // EN_CHANGE coalescer. On a 200 MB file this drops the
            // synchronous WM_CHAR cost from O(N) to O(1).
            UpdateColInfo(hWnd);
            RequestEditUiRefresh(hMainWnd);
            return defaultResult;
        }
    }

    case WM_PASTE: {
        int   textLength = GetWindowTextLength(hWnd);
        DWORD start, end;
        SendMessage(hWnd, EM_GETSEL, (WPARAM)&start, (LPARAM)&end);
        if (textLength > 0 && start == 0 && end >= (DWORD)textLength) {
            if (MessageBox(hWnd, L"Replace entire document?", L"Paste",
                           MB_YESNO | MB_ICONWARNING) == IDNO) return 0;
        }

        if (OpenClipboard(NULL)) {
            HANDLE hData = GetClipboardData(CF_UNICODETEXT);
            if (hData) {
                wchar_t* pClip = (wchar_t*)GlobalLock(hData);
                if (pClip) {
                    wstring in(pClip), out;
                    for (size_t i = 0; i < in.length(); ++i) {
                        if      (in[i] == L'\t') out += L"    ";
                        else if (in[i] == L'\n') {
                            if (i == 0 || in[i-1] != L'\r') out += L'\r';
                            out += L'\n';
                        } else out += in[i];
                    }
                    DWORD pStart;
                    SendMessage(hWnd, EM_GETSEL, (WPARAM)&pStart, 0);
                    DWORD pasteStart = 0, pasteEnd = 0;
                    SendMessage(hWnd, EM_GETSEL, (WPARAM)&pasteStart, (LPARAM)&pasteEnd);
                    EditCommand pasteCommand = BeginReplaceCommand(
                        hWnd, pasteStart, pasteEnd, out, pasteStart, pasteEnd);
                    SendMessage(hWnd, EM_REPLACESEL, TRUE, (LPARAM)out.c_str());
                    CommitEditCommand(tab, pasteCommand, false);
                    DWORD pEnd;
                    SendMessage(hWnd, EM_GETSEL, 0, (LPARAM)&pEnd);

                    int lineS = (int)SendMessage(hWnd, EM_LINEFROMCHAR, pStart, 0);
                    int lineE = (int)SendMessage(hWnd, EM_LINEFROMCHAR, pEnd,   0);
                    SetProp(hWnd, L"FlashLine",  (HANDLE)(DWORD_PTR)lineS);
                    SetProp(hWnd, L"FlashEnd",   (HANDLE)(DWORD_PTR)lineE);
                    SetProp(hWnd, L"FlashTimer", (HANDLE)15);
                    SetProp(hWnd, L"FlashColor", (HANDLE)(DWORD_PTR)RGB(80, 255, 80));
                    GlobalUnlock(hData);
                }
            }
            CloseClipboard();
        }
        tab->bModified = true;
        UpdateTitle(hMainWnd);
        // v4.34: paste — heavy mutation, but the user just performed an
        // intentional discrete action; one frame of latency is invisible.
        UpdateColInfo(hWnd);
        RequestEditUiRefresh(hMainWnd);
        // Defer the relayout so a paste-then-type burst doesn't trigger
        // two child re-layouts.
        SetTimer(hMainWnd, IDT_GUTTER_LAYOUT_DEFER, 100, NULL);
        return 0;
    }

    // =========================================================================
    //  WM_PAINT — Piece Table integration
    //  cachedDoc is refreshed from the piece table (pt.GetVirtualText()) when
    //  cachedDocDirty is true, instead of calling GetWindowText again.
    // =========================================================================
    case WM_PAINT: {
        if (!g_SyntaxHighlighting) break;

        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        RECT rc;
        GetClientRect(hWnd, &rc);
        int w = rc.right - rc.left;
        int h = rc.bottom - rc.top;

        if (w > 0 && h > 0) {
            MemoryDC memDC(hdc, w, h);
            if (memDC.isValid()) {
                FillRect(memDC, &rc, hBackBrush);
                SendMessage(hWnd, WM_PRINTCLIENT, (WPARAM)memDC.get(), PRF_CLIENT);

                {
                    ScopedSelectObject selFont(memDC, hEditorFont);
                    SIZE cz;
                    GetTextExtentPoint32(memDC, L"A", 1, &cz);
                    int first    = (int)SendMessage(hWnd, EM_GETFIRSTVISIBLELINE, 0, 0);
                    int total    = (int)SendMessage(hWnd, EM_GETLINECOUNT, 0, 0);
                    int xOff     = GetScrollPos(hWnd, SB_HORZ);
                    int lineH    = (cz.cy > 0) ? cz.cy : 1;
                    int visLines = (h / lineH) + 1;
                    SetBkMode(memDC, TRANSPARENT);

                    // --- FLASH RENDERER ---
                    int fTimer = (int)(DWORD_PTR)GetProp(hWnd, L"FlashTimer");
                    if (fTimer > 0) {
                        int      fS   = (int)(DWORD_PTR)GetProp(hWnd, L"FlashLine");
                        int      fE   = (int)(DWORD_PTR)GetProp(hWnd, L"FlashEnd");
                        COLORREF fCol = (COLORREF)(DWORD_PTR)GetProp(hWnd, L"FlashColor");
                        ScopedGdiObject hFlash(CreateSolidBrush(fCol));
                        if (hFlash.isValid()) {
                            for (int i = fS; i <= fE; i++) {
                                if (i >= first && i < first + visLines) {
                                    RECT fR = { 0, (i - first) * lineH,
                                                w, (i - first + 1) * lineH };
                                    FrameRect(memDC, &fR, (HBRUSH)hFlash.get());
                                }
                            }
                        }
                        SetProp(hWnd, L"FlashTimer", (HANDLE)(DWORD_PTR)(fTimer - 1));
                        InvalidateRect(hWnd, NULL, FALSE);
                    }

                    // --- JUMP HIGHLIGHT RENDERER ---
                    int jTimer = (int)(DWORD_PTR)GetProp(hWnd, L"HighlightTimer");
                    if (jTimer > 0) {
                        int hLine = (int)(DWORD_PTR)GetProp(hWnd, L"HighlightLine");
                        if (hLine >= first && hLine < first + visLines) {
                            int yHigh = (hLine - first) * lineH;
                            ScopedGdiObject hGreen(CreateSolidBrush(RGB(0, 255, 0)));
                            if (hGreen.isValid()) {
                                RECT topBar = { 0, yHigh,              w, yHigh + 2       };
                                RECT botBar = { 0, yHigh + lineH - 2,  w, yHigh + lineH   };
                                FillRect(memDC, &topBar, (HBRUSH)hGreen.get());
                                FillRect(memDC, &botBar, (HBRUSH)hGreen.get());
                            }
                        }
                        SetProp(hWnd, L"HighlightTimer", (HANDLE)(DWORD_PTR)(jTimer - 1));
                        InvalidateRect(hWnd, NULL, FALSE);
                    }

                    // --- SYNTAX RENDERER (v4.13: viewport-aware piece table window) ---
                    //
                    // Instead of flattening the entire document via
                    // tab->pt.GetVirtualText() (O(N) for an N-character document),
                    // we materialise ONLY the characters that are currently
                    // visible on screen plus a small safety buffer at each end.
                    //
                    // The visible character range is derived from the EDIT
                    // control's own line bookkeeping:
                    //   firstChar = EM_LINEINDEX(first)
                    //   lastChar  = EM_LINEINDEX(first + visLines)
                    //   lastLen   = EM_LINELENGTH(lastChar)
                    // Then padded by VIEWPORT_SAFETY_CHARS at each end so that
                    // bracket matching, identifier scanning, and look-behind /
                    // look-ahead heuristics still have a couple of words of
                    // slack to work with.
                    //
                    // The window is materialised via tab->pt.GetVirtualSpan(),
                    // which is O(log N + S) where S is the span length —
                    // typically a few thousand wchar_t regardless of how many
                    // millions of characters the full document contains.
                    //
                    // cachedDoc is reused across paints when the (offset, len)
                    // pair has not moved AND no tracked edit invalidated the
                    // window.  Idle repaints (caret blink, hover) therefore
                    // perform zero piece-table work.
                    DWORD selStart;
                    SendMessage(hWnd, EM_GETSEL, (WPARAM)&selStart, 0);

                    // Compute the visible span [spanStart, spanStart+spanLen)
                    // in absolute document character coordinates.
                    static constexpr size_t VIEWPORT_SAFETY_CHARS = 64;

                    int firstCharIdx = (int)SendMessage(hWnd, EM_LINEINDEX, first, 0);
                    if (firstCharIdx < 0) firstCharIdx = 0;

                    int lastVisLine = first + visLines;
                    if (total > 0 && lastVisLine >= total) lastVisLine = total - 1;
                    if (lastVisLine < first) lastVisLine = first;

                    int lastCharIdx = (int)SendMessage(hWnd, EM_LINEINDEX, lastVisLine, 0);
                    int lastLineLen = (lastCharIdx >= 0)
                                        ? (int)SendMessage(hWnd, EM_LINELENGTH, lastCharIdx, 0)
                                        : 0;

                    size_t docLen   = tab->pt.Length();
                    size_t spanEnd  = (lastCharIdx >= 0)
                                        ? (size_t)(lastCharIdx + lastLineLen + 2)
                                        : docLen;
                    if (spanEnd > docLen) spanEnd = docLen;

                    // Pad both ends so bracket scans / identifier scans don't
                    // truncate at the viewport edge.
                    size_t spanStart = (firstCharIdx > (int)VIEWPORT_SAFETY_CHARS)
                                        ? (size_t)firstCharIdx - VIEWPORT_SAFETY_CHARS
                                        : 0;
                    if (spanEnd + VIEWPORT_SAFETY_CHARS <= docLen)
                        spanEnd += VIEWPORT_SAFETY_CHARS;
                    else
                        spanEnd = docLen;

                    size_t spanLen = (spanEnd > spanStart) ? (spanEnd - spanStart) : 0;

                    // Rebuild the window only when something actually changed.
                    bool windowMoved = (tab->cachedDocOffset  != spanStart) ||
                                       (tab->cachedDocSpanLen != spanLen);
                    if (tab->cachedDocDirty || windowMoved) {
                        if (tab->ptDirty) tab->SyncPieceTableFromEdit();
                        tab->cachedDoc        = tab->pt.GetVirtualSpan(spanStart, spanLen);
                        tab->cachedDocOffset  = spanStart;
                        tab->cachedDocSpanLen = tab->cachedDoc.size();
                        tab->cachedDocDirty   = false;
                    }
                    const wstring& doc = tab->cachedDoc;

                    // v4.17 - Whole-document bracket matching with unmatched detection.
                    //   Fast path : caret AND match both inside cachedDoc -> local scan, O(window).
                    //   Slow path : caret in window, match outside        -> chunked PT scan.
                    //   Cold path : caret outside window (rare)           -> chunked PT scan.
                    //
                    // If the caret is on a bracket but no partner exists anywhere
                    // in the document, we publish an "Unmatched" notice to the
                    // title bar (open bracket = no closing, close bracket = no
                    // opening).  The on-screen highlight branch is unchanged.
                    int  matchIdx        = -1;
                    bool caretOnBracket  = false;
                    bool caretIsOpener   = false;   // true = '(' '{' '['
                    if (selStart > 0) {
                        size_t selAbs   = (size_t)selStart - 1;

                        // Identify whether the caret sits on a bracket and its
                        // direction, using the cached window when possible to
                        // avoid an extra GetVirtualSpan call.
                        wchar_t bch = 0;
                        if (selAbs >= tab->cachedDocOffset &&
                            selAbs <  tab->cachedDocOffset + doc.length()) {
                            bch = doc[selAbs - tab->cachedDocOffset];
                        } else {
                            wstring one = tab->pt.GetVirtualSpan(selAbs, 1);
                            if (!one.empty()) bch = one[0];
                        }
                        if (bch == L'(' || bch == L'{' || bch == L'[') {
                            caretOnBracket = true; caretIsOpener = true;
                        } else if (bch == L')' || bch == L'}' || bch == L']') {
                            caretOnBracket = true; caretIsOpener = false;
                        }

                        bool inWindow = (selAbs >= tab->cachedDocOffset &&
                                         selAbs <  tab->cachedDocOffset + doc.length());
                        if (inWindow) {
                            int local = FindMatchingBracket(
                                doc, (int)(selAbs - tab->cachedDocOffset));
                            if (local >= 0)
                                matchIdx = (int)tab->cachedDocOffset + local;
                        }
                        // Local windowed scan failed (or caret outside the
                        // window) - fall back to the full piece-table scan.
                        if (matchIdx < 0 && caretOnBracket)
                            matchIdx = FindMatchingBracketAbs(tab->pt, selAbs);
                    }

                    // ---- Title-bar publication ---------------------------------
                    // Three states encoded in the (open,close) cache pair:
                    //   ( >=0, >=0 )  matched        -> "Match: open L.. <-> close L.."
                    //   ( -2 , line)  unmatched open -> "Unmatched '(' at L..  (no closing)"
                    //   ( -3 , line)  unmatched close-> "Unmatched ')' at L..  (no opening)"
                    //   ( -1 , -1  )  not on bracket -> title left to other publishers
                    if (matchIdx >= 0) {
                        int openAbs  = (int)selStart - 1;
                        int closeAbs = matchIdx;
                        if (openAbs > closeAbs) {
                            int tmp = openAbs; openAbs = closeAbs; closeAbs = tmp;
                        }
                        if (openAbs  != tab->lastMatchOpenAbs ||
                            closeAbs != tab->lastMatchCloseAbs) {
                            int openLine  = (int)SendMessage(hWnd, EM_LINEFROMCHAR,
                                                             (WPARAM)openAbs,  0) + 1;
                            int closeLine = (int)SendMessage(hWnd, EM_LINEFROMCHAR,
                                                             (WPARAM)closeAbs, 0) + 1;
                            wchar_t mbuf[160];
                            swprintf(mbuf, 160,
                                     L"Tiny Fantail | Match: open L%d  <->  close L%d",
                                     openLine, closeLine);
                            HWND hMainWnd = GetAncestor(hWnd, GA_ROOT);
                            if (hMainWnd) SetWindowTextW(hMainWnd, mbuf);
                            tab->lastMatchOpenAbs  = openAbs;
                            tab->lastMatchCloseAbs = closeAbs;
                        }
                    } else if (caretOnBracket) {
                        // Bracket has no partner anywhere in the document.
                        int  bAbs    = (int)selStart - 1;
                        int  bLine   = (int)SendMessage(hWnd, EM_LINEFROMCHAR,
                                                        (WPARAM)bAbs, 0) + 1;
                        int  sentinel = caretIsOpener ? -2 : -3;
                        if (tab->lastMatchOpenAbs != sentinel ||
                            tab->lastMatchCloseAbs != bLine) {
                            // Re-fetch the bracket char for an accurate label.
                            wchar_t bch = 0;
                            if ((size_t)bAbs >= tab->cachedDocOffset &&
                                (size_t)bAbs <  tab->cachedDocOffset + doc.length()) {
                                bch = doc[(size_t)bAbs - tab->cachedDocOffset];
                            } else {
                                wstring one = tab->pt.GetVirtualSpan((size_t)bAbs, 1);
                                if (!one.empty()) bch = one[0];
                            }
                            wchar_t mbuf[160];
                            if (caretIsOpener) {
                                swprintf(mbuf, 160,
                                    L"Tiny Fantail | Unmatched '%lc' at L%d  (no closing)",
                                    bch, bLine);
                            } else {
                                swprintf(mbuf, 160,
                                    L"Tiny Fantail | Unmatched '%lc' at L%d  (no opening)",
                                    bch, bLine);
                            }
                            HWND hMainWnd = GetAncestor(hWnd, GA_ROOT);
                            if (hMainWnd) SetWindowTextW(hMainWnd, mbuf);
                            tab->lastMatchOpenAbs  = sentinel;
                            tab->lastMatchCloseAbs = bLine;
                        }
                    } else if (tab->lastMatchOpenAbs != -1 ||
                               tab->lastMatchCloseAbs != -1) {
                        tab->lastMatchOpenAbs  = -1;
                        tab->lastMatchCloseAbs = -1;
                        // Title left for other publishers (file load, indexer).
                    }


                    for (int i = 0; i <= visLines; ++i) {
                        int lIdx = first + i;
                        if (lIdx >= total) break;
                        int yTop = i * lineH;
                        int cIdx = (int)SendMessage(hWnd, EM_LINEINDEX, lIdx, 0);
                        int lLen = (int)SendMessage(hWnd, EM_LINELENGTH, cIdx, 0);
                        // v4.34: cap per-line tokenisation. Anything past
                        // the right viewport edge is clipped by GDI; the
                        // old loop still tokenised the entire line, which
                        // ran into hundreds of ms on minified one-line files.
                        // v4.35 S3: clamp into [0, MAX]. EM_LINELENGTH on
                        // a deleted/invalid line can return -1 on Wine and
                        // older comctl32; using that as a count would read
                        // past the line buffer in the inner per-char loop.
                        if (lLen < 0) lLen = 0;
                        if (lLen > TF_PAINT_MAX_LINE_CHARS)
                            lLen = TF_PAINT_MAX_LINE_CHARS;

                        if (tab && tab->errorLine == lIdx + 1) {
                            RECT errR = { 0, yTop, w, yTop + lineH };
                            FrameRect(memDC, &errR, hMatchBrush);
                        }

                        if (lLen > 0) {
                            if (lineBuf.size() < (size_t)lLen + 2)
                                lineBuf.resize(lLen + 2);
                            *(WORD*)lineBuf.data() = (WORD)(lLen + 1);
                            SendMessage(hWnd, EM_GETLINE, lIdx, (LPARAM)lineBuf.data());
                            wstring word;
                            for (int j = 0; j < lLen; ++j) {
                                int     x    = (j * cz.cx) - xOff + 4;
                                wchar_t c    = lineBuf[j];
                                int     gIdx = cIdx + j;

                                if (c == L' ') {
                                    int  yDot = yTop + (lineH / 2);
                                    RECT dotR = { x, yDot, x + 2, yDot + 2 };
                                    FillRect(memDC, &dotR, hDotBrush);
                                }
                                if (gIdx == (int)selStart - 1 || gIdx == matchIdx) {
                                    RECT brR = { x, yTop, x + cz.cx, yTop + lineH };
                                    FrameRect(memDC, &brR, hMatchBrush);
                                }
                                if (iswalpha(c) || c == L'_') {
                                    word += c;
                                    if (j == lLen - 1 ||
                                        (!iswalpha(lineBuf[j+1]) &&
                                         lineBuf[j+1] != L'_')) {
                                        if (g_Keywords.count(word)) {
                                            SetTextColor(memDC, KEYWORD_COLOR);
                                            TextOut(memDC,
                                                x - (int)(word.length() - 1) * cz.cx,
                                                yTop, word.c_str(), (int)word.length());
                                        }
                                        word.clear();
                                    }
                                } else if (iswdigit(c)) {
                                    SetTextColor(memDC, CYAN_COLOR);
                                    TextOut(memDC, x, yTop, &lineBuf[j], 1);
                                } else {
                                    word.clear();
                                }
                            }
                        }
                    }

                    // ---------------------------------------------------------
                    //  v4.30 — BRACKET-PAIR CONNECTOR  (L-shaped polyline)
                    //  Draws an orthogonal guide that physically links the
                    //  opening bracket to its partner, even when the two live
                    //  in different columns:
                    //
                    //      int main () {
                    //                   |
                    //                   |
                    //      +------------+
                    //      |
                    //      }
                    //
                    //  Path:  (xOpen, yOpenMid)
                    //      -> (xOpen, yCloseMid)        vertical drop
                    //      -> (xClose, yCloseMid)       horizontal jog
                    //  When the brackets share a column the jog has zero
                    //  length and the result collapses to a single vertical
                    //  segment.  Drawn AFTER the per-line text pass so syntax
                    //  highlighting cannot overpaint it.
                    // ---------------------------------------------------------
                    if (matchIdx >= 0 && caretOnBracket) {
                        int openAbs  = (int)selStart - 1;
                        int closeAbs = matchIdx;
                        if (openAbs > closeAbs) {
                            int tmp = openAbs; openAbs = closeAbs; closeAbs = tmp;
                        }
                        int openLine  = (int)SendMessage(hWnd, EM_LINEFROMCHAR,
                                                         (WPARAM)openAbs,  0);
                        int closeLine = (int)SendMessage(hWnd, EM_LINEFROMCHAR,
                                                         (WPARAM)closeAbs, 0);
                        if (closeLine > openLine) {
                            int openLineStart  = (int)SendMessage(hWnd, EM_LINEINDEX,
                                                                  openLine,  0);
                            int closeLineStart = (int)SendMessage(hWnd, EM_LINEINDEX,
                                                                  closeLine, 0);
                            int openCol  = openAbs  - openLineStart;
                            int closeCol = closeAbs - closeLineStart;

                            // Anchor X at the centre of each bracket cell.
                            int xOpen  = (openCol  * cz.cx) - xOff + 4 + (cz.cx / 2);
                            int xClose = (closeCol * cz.cx) - xOff + 4 + (cz.cx / 2);

                            // Vertical anchors at the vertical centre of each
                            // bracket's row, so the connector visibly touches
                            // the glyph rather than floating above/below it.
                            int yOpen  = (openLine  - first) * lineH + (lineH / 2);
                            int yClose = (closeLine - first) * lineH + (lineH / 2);

                            // Render only when at least one endpoint or some
                            // portion of the path is on screen.
                            bool anyVisible = (yOpen  >= 0 && yOpen  <= h) ||
                                              (yClose >= 0 && yClose <= h) ||
                                              (yOpen  <  0 && yClose >  h);
                            if (anyVisible) {
                                ScopedGdiObject hMatchPen(
                                    CreatePen(PS_SOLID, 2, RGB(80, 255, 120)));
                                if (hMatchPen.isValid()) {
                                    HGDIOBJ oldPen = SelectObject(memDC,
                                                                  hMatchPen.get());

                                    // L-path: down from opener, then across
                                    // (perpendicular jog) to closer column.
                                    POINT pts[3] = {
                                        { xOpen,  yOpen  },
                                        { xOpen,  yClose },
                                        { xClose, yClose }
                                    };
                                    Polyline(memDC, pts, 3);

                                    SelectObject(memDC, oldPen);
                                }
                            }
                        }
                    }
                }

                memDC.blitRegionTo(hdc,
                    ps.rcPaint.left, ps.rcPaint.top,
                    ps.rcPaint.right  - ps.rcPaint.left,
                    ps.rcPaint.bottom - ps.rcPaint.top,
                    ps.rcPaint.left, ps.rcPaint.top);
            }
        }

        EndPaint(hWnd, &ps);
        return 0;
    }

    case WM_ERASEBKGND: return 1;

    case WM_KILLFOCUS: {
        HWND hNewFocus = (HWND)wParam;
        if (hNewFocus != g_hAutofillListBox && hNewFocus != g_hAutofillPopup)
            HideAutofillPopup();
        break;
    }

    default:
        // v4.33: split the old combined handler into two paths:
        //   (a) Pure scroll input (wheel / scrollbar) — caret does NOT move,
        //       so skip RefreshAllIndicators entirely and coalesce the gutter
        //       + edit repaint through a 16 ms one-shot timer. This caps
        //       scroll repaints at ~60 Hz regardless of how fast the user
        //       spins the wheel or drags the thumb.
        //   (b) Caret-affecting input (KEYUP / mouse click) — must refresh
        //       column/line/char/word indicators immediately, but we still
        //       coalesce the heavy edit-client invalidate via the same timer.
        if (uMsg == WM_VSCROLL    || uMsg == WM_HSCROLL ||
            uMsg == WM_MOUSEWHEEL || uMsg == WM_MOUSEHWHEEL) {
            LRESULT res = CallWindowProc(OldEditProc, hWnd, uMsg, wParam, lParam);
            // One-shot 16 ms timer — re-arming an existing timer just resets
            // its countdown, naturally collapsing wheel bursts into one paint.
            SetTimer(hWnd, SCROLL_REPAINT_TIMER_ID, 16, NULL);
            return res;
        }
        if (uMsg == WM_KEYUP     || uMsg == WM_LBUTTONDOWN ||
            uMsg == WM_LBUTTONUP) {
            LRESULT res = CallWindowProc(OldEditProc, hWnd, uMsg, wParam, lParam);
            RefreshAllIndicators(hWnd);
            // Coalesce the gutter/edit repaint with any pending scroll repaint.
            SetTimer(hWnd, SCROLL_REPAINT_TIMER_ID, 16, NULL);
            return res;
        }
    }
    return CallWindowProc(OldEditProc, hWnd, uMsg, wParam, lParam);
}


// =============================================================================
//  TAB MANAGEMENT
// =============================================================================
// =============================================================================
//  SIDEBAR WIDTH — REGISTRY PERSISTENCE
//  Key: HKCU\Software\LittleFantail\Settings  Value: SidebarWidth (DWORD)
// =============================================================================
static const wchar_t* k_RegSubKey = L"Software\\LittleFantail\\Settings";
static const wchar_t* k_RegValue  = L"SidebarWidth";

void SaveSidebarWidth() {
    HKEY hKey = NULL;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, k_RegSubKey, 0, NULL,
                         REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL,
                         &hKey, NULL) == ERROR_SUCCESS) {
        // Save the current visible width (or saved width if currently hidden).
        DWORD dwW = (DWORD)(g_sidebarVisible ? g_sidebarWidth : g_savedSidebarWidth);
        RegSetValueExW(hKey, k_RegValue, 0, REG_DWORD,
                       (const BYTE*)&dwW, sizeof(dwW));

        // Save the pre-hide width so we can restore it on next show.
        DWORD dwS = (DWORD)g_savedSidebarWidth;
        RegSetValueExW(hKey, L"SidebarSavedWidth", 0, REG_DWORD,
                       (const BYTE*)&dwS, sizeof(dwS));

        // Save the visibility flag so the panel opens in the same state.
        DWORD dwVis = g_sidebarVisible ? 1u : 0u;
        RegSetValueExW(hKey, L"SidebarVisible", 0, REG_DWORD,
                       (const BYTE*)&dwVis, sizeof(dwVis));

        RegCloseKey(hKey);
    }
}

void LoadSidebarWidth() {
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, k_RegSubKey, 0,
                       KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
        // Load last visible width.
        DWORD dwW  = SIDEBAR_DEFAULT_WIDTH;
        DWORD type = REG_DWORD, cb = sizeof(dwW);
        RegQueryValueExW(hKey, k_RegValue, NULL, &type, (BYTE*)&dwW, &cb);

        // Load saved (pre-hide) width separately.
        DWORD dwS  = SIDEBAR_DEFAULT_WIDTH;
        type = REG_DWORD; cb = sizeof(dwS);
        RegQueryValueExW(hKey, L"SidebarSavedWidth", NULL, &type, (BYTE*)&dwS, &cb);

        // Load visibility flag (0 = hidden, 1 = visible).
        DWORD dwVis = 1;
        type = REG_DWORD; cb = sizeof(dwVis);
        RegQueryValueExW(hKey, L"SidebarVisible", NULL, &type, (BYTE*)&dwVis, &cb);

        RegCloseKey(hKey);

        // Clamp widths to sane range.
        auto clamp = [](DWORD v) -> int {
            if (v > 0 && v < (DWORD)SIDEBAR_MIN_WIDTH) v = SIDEBAR_MIN_WIDTH;
            if (v > 600) v = 600;
            return (int)v;
        };

        g_sidebarVisible    = (dwVis != 0);
        g_savedSidebarWidth = clamp(dwS > 0 ? dwS : dwW);
        g_sidebarWidth      = g_sidebarVisible ? clamp(dwW) : 0;
    }
}

// =============================================================================
//  APPLY SIDEBAR WIDTH
//  One entry point that repositions every layout child via DeferWindowPos.
//  Must only be called from the UI thread.
// =============================================================================
// These are the layout-aware controls declared as statics inside WindowProc.
// Expose them as module-level so ApplySidebarWidth can reach them.
static HWND hGlobalLbl       = NULL;
static HWND hGlobalCmdInput  = NULL;
static HWND hGlobalCheckBtn  = NULL;
static HWND hGlobalExecBtn   = NULL;
static HWND hGlobalSyntaxBtn = NULL;
static HWND hGlobalSearchLbl = NULL;
static HWND hGlobalSearchIn  = NULL;
static HWND hGlobalSearchBtn = NULL;
static HWND hGlobalSearchUp  = NULL;

void ApplySidebarWidth(HWND hMain, int newWidth, bool saveNow) {
    // Drag-resize clamp: never zero — only the toggle button (IDC_SIDEBAR_TOGGLE) may
    // set the width to 0.  Dragging below SIDEBAR_MIN_WIDTH snaps open to the minimum.
    if (newWidth < SIDEBAR_MIN_WIDTH)
        newWidth = SIDEBAR_MIN_WIDTH;
    if (newWidth > 600)
        newWidth = 600;

    // Keep g_savedSidebarWidth current while dragging so toggle-hide remembers the
    // last position the user dragged to.
    g_savedSidebarWidth = newWidth;
    g_sidebarWidth      = newWidth;
    g_sidebarVisible    = true; // ApplySidebarWidth always results in a visible sidebar

    if (saveNow) SaveSidebarWidth();

    // Trigger a full layout recalc via WM_SIZE (which reads g_sidebarWidth).
    RECT rc;
    GetClientRect(hMain, &rc);
    SendMessage(hMain, WM_SIZE, SIZE_RESTORED,
                MAKELPARAM(rc.right, rc.bottom));
}

// =============================================================================
//  SPLITTER BAR WINDOW PROCEDURE
//  A narrow (SPLITTER_WIDTH px) child window that sits between the sidebar and
//  the editor area.  It handles its own mouse dragging, hover effect, and snap.
// =============================================================================
static const wchar_t* k_SplitterClass = L"LittleFantailSplitter";

LRESULT CALLBACK SplitterWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    // Per-instance drag state (only one splitter exists, statics are fine).
    static bool s_dragging        = false;
    static bool s_hover           = false;
    static bool s_tracking        = false;  // for WM_MOUSELEAVE
    static int  s_dragStartMouseX = 0;
    static int  s_dragStartSideW  = 0;

    // Colours
    static const COLORREF CLR_NORMAL  = RGB(60, 60, 60);
    static const COLORREF CLR_HOVER   = RGB(100, 140, 200);
    static const COLORREF CLR_DRAG    = RGB(130, 170, 230);

    switch (uMsg) {

    case WM_SETCURSOR:
        SetCursor(LoadCursor(NULL, IDC_SIZEWE));
        return TRUE;   // suppress DefWindowProc cursor reset

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);
        COLORREF clr = s_dragging ? CLR_DRAG : (s_hover ? CLR_HOVER : CLR_NORMAL);
        HBRUSH hBr = CreateSolidBrush(clr);
        FillRect(hdc, &rc, hBr);
        DeleteObject(hBr);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_MOUSEMOVE: {
        // Start tracking so we get WM_MOUSELEAVE when the cursor leaves.
        if (!s_tracking) {
            TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hwnd, 0 };
            TrackMouseEvent(&tme);
            s_tracking = true;
        }
        if (!s_hover && !s_dragging) {
            s_hover = true;
            InvalidateRect(hwnd, NULL, FALSE);
        }
        // Only allow drag-resize when the sidebar is visible via the toggle button.
        // This prevents the user accidentally dragging it to the collapse threshold
        // and causing an unintended hide (toggle button is the only hide path).
        if (s_dragging && g_sidebarVisible) {
            POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            ClientToScreen(hwnd, &pt);
            HWND hMain = GetParent(hwnd);
            POINT ptMain = pt;
            ScreenToClient(hMain, &ptMain);
            int newW = ptMain.x;   // cursor X in main-window coords = new sidebar width
            ApplySidebarWidth(hMain, newW, false);
        } else if (s_dragging && !g_sidebarVisible) {
            // Sidebar is hidden; abort the drag silently.
            ReleaseCapture();
            s_dragging = false;
            InvalidateRect(hwnd, NULL, FALSE);
        }
        return 0;
    }

    case WM_MOUSELEAVE:
        s_tracking = false;
        if (!s_dragging && s_hover) {
            s_hover = false;
            InvalidateRect(hwnd, NULL, FALSE);
        }
        return 0;

    case WM_LBUTTONDOWN: {
        SetCapture(hwnd);
        s_dragging        = true;
        s_dragStartMouseX = GET_X_LPARAM(lParam);
        s_dragStartSideW  = g_sidebarWidth;
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    }

    case WM_LBUTTONUP:
        if (s_dragging) {
            ReleaseCapture();
            s_dragging = false;
            s_hover    = false;
            // Save final width to the registry.
            HWND hMain = GetParent(hwnd);
            SaveSidebarWidth();
            InvalidateRect(hwnd, NULL, FALSE);
            // If the cursor is still over the splitter, re-enable hover.
            POINT pt; GetCursorPos(&pt);
            RECT rcScr; GetWindowRect(hwnd, &rcScr);
            if (PtInRect(&rcScr, pt)) { s_hover = true; InvalidateRect(hwnd, NULL, FALSE); }
        }
        return 0;

    case WM_CAPTURECHANGED:
        if (s_dragging) {
            s_dragging = false;
            InvalidateRect(hwnd, NULL, FALSE);
        }
        return 0;

    default:
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
}

// =============================================================================
//  SIDEBAR — DIRECTORY TREE IMPLEMENTATION
//  Background thread enumerates the directory via std::filesystem::recursive_directory_iterator
//  and posts WM_DIRECTORY_LOADED with a heap-allocated DirLoadResult to the main
//  window.  The UI thread populates the TreeView on receipt, keeping the message
//  pump responsive for arbitrarily deep directories.
// =============================================================================

static bool SamePathNoCase(const std::wstring& a, const std::wstring& b) {
    std::wstring na = fs::path(a).lexically_normal().wstring();
    std::wstring nb = fs::path(b).lexically_normal().wstring();
    return _wcsicmp(na.c_str(), nb.c_str()) == 0;
}

static std::wstring SidebarPathKey(const std::wstring& path) {
    std::wstring key = fs::path(path).lexically_normal().wstring();
    for (auto& c : key) c = ::towlower(c);
    return key;
}

static bool SidebarPathIsUnderRoot(const std::wstring& path, const std::wstring& root) {
    if (path.empty() || root.empty()) return false;
    if (SamePathNoCase(path, root)) return true;

    std::wstring p = SidebarPathKey(path);
    std::wstring r = SidebarPathKey(root);
    if (r.empty()) return false;

    wchar_t last = r.back();
    if (last != L'\\' && last != L'/') r.push_back(fs::path::preferred_separator);
    return p.size() > r.size() && p.compare(0, r.size(), r) == 0;
}

static std::wstring SidebarGetSelectedPath() {
    if (!g_hDirTree || !IsWindow(g_hDirTree)) return L"";
    HTREEITEM hSel = TreeView_GetSelection(g_hDirTree);
    if (!hSel) return L"";

    // Path lookup is now indirected through the managed map; lParam is unused.
    return SidebarPathForItem(hSel);
}

static HTREEITEM SidebarFindPathItemRecursive(HTREEITEM hItem, const std::wstring& targetPath) {
    while (hItem) {
        // Pull the canonical path out of g_TreeMap rather than touching lParam.
        const std::wstring& path = SidebarPathForItem(hItem);
        if (!path.empty() && SamePathNoCase(path, targetPath)) return hItem;

        HTREEITEM hChild = TreeView_GetChild(g_hDirTree, hItem);
        if (hChild) {
            HTREEITEM found = SidebarFindPathItemRecursive(hChild, targetPath);
            if (found) return found;
        }
        hItem = TreeView_GetNextSibling(g_hDirTree, hItem);
    }
    return NULL;
}

static HTREEITEM SidebarFindPathItem(const std::wstring& targetPath) {
    if (targetPath.empty() || !g_hDirTree || !IsWindow(g_hDirTree)) return NULL;
    return SidebarFindPathItemRecursive(TreeView_GetRoot(g_hDirTree), targetPath);
}

static bool IsValidFolderLeafName(const std::wstring& name) {
    if (name.empty() || name == L"." || name == L"..") return false;
    if (name.front() == L' ' || name.back() == L' ' || name.back() == L'.') return false;
    const std::wstring invalid = L"\\/:*?\"<>|";
    return name.find_first_of(invalid) == std::wstring::npos;
}

struct FolderNameDialogState {
    std::wstring value;
    bool accepted;
};

static LRESULT CALLBACK FolderNameDialogProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCTW* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        SetWindowLongPtr(hWnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
        HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

        HWND hLabel = CreateWindowExW(0, L"STATIC", L"Folder name:",
                                      WS_CHILD | WS_VISIBLE,
                                      14, 14, 280, 20, hWnd, NULL,
                                      GetModuleHandle(NULL), NULL);
        HWND hEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                     WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | WS_TABSTOP,
                                     14, 38, 300, 24, hWnd, (HMENU)IDC_AUTOFILL_INPUT,
                                     GetModuleHandle(NULL), NULL);
        HWND hOk = CreateWindowExW(0, L"BUTTON", L"Create",
                                   WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP,
                                   144, 78, 80, 28, hWnd, (HMENU)IDOK,
                                   GetModuleHandle(NULL), NULL);
        HWND hCancel = CreateWindowExW(0, L"BUTTON", L"Cancel",
                                       WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
                                       234, 78, 80, 28, hWnd, (HMENU)IDCANCEL,
                                       GetModuleHandle(NULL), NULL);
        SendMessage(hLabel, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessage(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessage(hOk, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessage(hCancel, WM_SETFONT, (WPARAM)hFont, TRUE);
        SetFocus(hEdit);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            wchar_t buffer[MAX_PATH] = {};
            GetDlgItemTextW(hWnd, IDC_AUTOFILL_INPUT, buffer, MAX_PATH);
            std::wstring name(buffer);
            if (!IsValidFolderLeafName(name)) {
                MessageBoxW(hWnd,
                            L"Use a normal folder name without slashes, reserved characters, trailing dots, or leading/trailing spaces.",
                            L"Invalid Folder Name", MB_OK | MB_ICONWARNING);
                return 0;
            }
            FolderNameDialogState* state =
                reinterpret_cast<FolderNameDialogState*>(GetWindowLongPtr(hWnd, GWLP_USERDATA));
            if (state) {
                state->value = name;
                state->accepted = true;
            }
            DestroyWindow(hWnd);
            return 0;
        }
        if (LOWORD(wParam) == IDCANCEL) {
            DestroyWindow(hWnd);
            return 0;
        }
        break;
    case WM_CLOSE:
        DestroyWindow(hWnd);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

static bool PromptForFolderName(HWND owner, std::wstring& outName) {
    static const wchar_t* kClassName = L"LittleFantailFolderNameDialog";
    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = FolderNameDialogProc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = kClassName;
        registered = RegisterClassExW(&wc) || GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    }
    if (!registered) return false;

    RECT rcOwner = {};
    GetWindowRect(owner, &rcOwner);
    int width = 340;
    int height = 150;
    int x = rcOwner.left + ((rcOwner.right - rcOwner.left) - width) / 2;
    int y = rcOwner.top + ((rcOwner.bottom - rcOwner.top) - height) / 2;

    FolderNameDialogState state = { L"", false };
    EnableWindow(owner, FALSE);
    HWND hDlg = CreateWindowExW(WS_EX_DLGMODALFRAME | WS_EX_TOPMOST,
                                kClassName, L"Create Folder",
                                WS_POPUP | WS_CAPTION | WS_SYSMENU,
                                x, y, width, height,
                                owner, NULL, GetModuleHandle(NULL), &state);
    if (!hDlg) {
        EnableWindow(owner, TRUE);
        return false;
    }

    ShowWindow(hDlg, SW_SHOW);
    UpdateWindow(hDlg);

    MSG msg;
    while (IsWindow(hDlg) && GetMessage(&msg, NULL, 0, 0) > 0) {
        if (!IsDialogMessage(hDlg, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    EnableWindow(owner, TRUE);
    SetForegroundWindow(owner);
    if (state.accepted) outName = state.value;
    return state.accepted;
}

static void SidebarSelectPath(const std::wstring& path) {
    HTREEITEM hItem = SidebarFindPathItem(path);
    if (hItem) {
        HTREEITEM hParent = TreeView_GetParent(g_hDirTree, hItem);
        while (hParent) {
            TreeView_Expand(g_hDirTree, hParent, TVE_EXPAND);
            hParent = TreeView_GetParent(g_hDirTree, hParent);
        }
        TreeView_SelectItem(g_hDirTree, hItem);
        TreeView_EnsureVisible(g_hDirTree, hItem);
    }
}

static void SidebarRefreshAfterDiskWrite(HWND hMainWnd, const std::wstring& filePath) {
    if (filePath.empty() || g_TreeRootDir.empty()) return;
    std::wstring parent = fs::path(filePath).parent_path().wstring();
    if (!parent.empty() && SidebarPathIsUnderRoot(parent, g_TreeRootDir)) {
        SidebarLoadDirectory(hMainWnd, g_TreeRootDir, true, filePath);
    }
}

// Background thread body: enumerate dirPath, push result into g_DirLoadQueue,
// then ring the WM_DIRECTORY_LOADED doorbell.
static void DirLoadThreadBody(std::unique_ptr<DirLoadParams> params) {
    // v4.11: exit early if shutdown is in progress.
    if (!g_appRunning.load()) return;

    auto result = std::make_unique<DirLoadResult>();
    result->hMainWnd = params->hMainWnd;
    result->rootDir  = params->dirPath;
    result->selectAfterLoad = params->selectAfterLoad;

    std::error_code ec;

    if (!params->createChildName.empty()) {
        fs::path parentDir = params->createParentDir.empty()
                             ? fs::path(params->dirPath)
                             : fs::path(params->createParentDir);
        fs::path newFolder = parentDir / params->createChildName;
        if (fs::exists(newFolder, ec)) {
            result->errorMessage = L"That folder already exists.";
        } else {
            ec.clear();
            if (!fs::create_directory(newFolder, ec)) {
                if (ec) {
                    std::string msg = ec.message();
                    result->errorMessage = L"Could not create folder:\n"
                        + std::wstring(msg.begin(), msg.end());
                } else {
                    result->errorMessage = L"Could not create folder.";
                }
            } else {
                result->selectAfterLoad = newFolder.wstring();
            }
        }
        ec.clear();
    }

    try {
        fs::recursive_directory_iterator it(
            params->dirPath,
            fs::directory_options::skip_permission_denied,
            ec);
        fs::recursive_directory_iterator end;
        for (; it != end && !ec; it.increment(ec)) {
            if (ec) break;
            const auto& entry = *it;
            DirLoadResult::Entry e;
            std::error_code typeEc;
            e.isDir      = entry.is_directory(typeEc);
            e.fullPath   = entry.path().wstring();
            e.parentPath = entry.path().parent_path().wstring();
            e.name       = entry.path().filename().wstring();
            e.depth      = it.depth();
            e.hasChildren = false;
            result->entries.push_back(std::move(e));
        }
    } catch (...) {}

    std::unordered_set<std::wstring> parentsWithChildren;
    for (const auto& e : result->entries)
        parentsWithChildren.insert(SidebarPathKey(e.parentPath));
    for (auto& e : result->entries)
        e.hasChildren = e.isDir && parentsWithChildren.count(SidebarPathKey(e.fullPath)) != 0;

    // Push to queue and ring the doorbell — lParam is intentionally null.
    if (!g_appRunning.load()) return;   // v4.11: skip post if shutting down
    HWND hwnd = result->hMainWnd;
    g_DirLoadQueue.push(std::move(result));
    PostMessage(hwnd, WM_DIRECTORY_LOADED, 0, 0);
}

// Kick off an async directory load.  Safe to call from the UI thread at any time.
void SidebarLoadDirectory(HWND hMainWnd, const std::wstring& dirPath,
                          bool forceRefresh,
                          const std::wstring& selectAfterLoad,
                          const std::wstring& createChildName,
                          const std::wstring& createParentDir) {
    if (dirPath.empty()) return;
    if (!g_hDirTree || !IsWindow(g_hDirTree)) return;

    if (!forceRefresh && SamePathNoCase(g_TreeRootDir, dirPath)) return;

    auto params = std::make_unique<DirLoadParams>();
    params->hMainWnd = hMainWnd;
    params->dirPath  = dirPath;
    params->createParentDir = createParentDir;
    params->createChildName = createChildName;
    params->selectAfterLoad = selectAfterLoad;

    // v4.11: use tracked thread (no detach).
    g_ThreadMgr.spawn([p = std::move(params)]() mutable {
        DirLoadThreadBody(std::move(p));
    });
}

static bool SidebarEntryNameLess(const DirLoadResult::Entry& a, const DirLoadResult::Entry& b) {
    if (a.isDir != b.isDir) return a.isDir && !b.isDir;
    std::wstring la = a.name, lb = b.name;
    for (auto& c : la) c = ::towlower(c);
    for (auto& c : lb) c = ::towlower(c);
    return la < lb;
}

static void SidebarInsertTreeChildren(
    const std::wstring& parentPath,
    HTREEITEM hParent,
    const DirLoadResult& result,
    const std::unordered_map<std::wstring, std::vector<size_t>>& childrenByParent) {

    auto it = childrenByParent.find(SidebarPathKey(parentPath));
    if (it == childrenByParent.end()) return;

    std::vector<size_t> childIndexes = it->second;
    std::sort(childIndexes.begin(), childIndexes.end(),
        [&result](size_t ia, size_t ib) {
            return SidebarEntryNameLess(result.entries[ia], result.entries[ib]);
        });

    for (size_t idx : childIndexes) {
        const auto& e = result.entries[idx];

        TVINSERTSTRUCT tvi = {};
        tvi.hParent        = hParent ? hParent : TVI_ROOT;
        tvi.hInsertAfter   = TVI_LAST;
        tvi.item.mask      = TVIF_TEXT | TVIF_PARAM | TVIF_STATE | TVIF_CHILDREN;
        tvi.item.stateMask = TVIS_BOLD;
        tvi.item.cChildren = e.hasChildren ? I_CHILDRENCALLBACK : 0;

        // Path payload now lives in g_TreeMap; lParam is intentionally zeroed
        // so any stray legacy reinterpret_cast would crash loudly instead of
        // silently corrupting heap memory.
        tvi.item.lParam = 0;

        if (e.isDir) tvi.item.state = TVIS_BOLD;
        tvi.item.pszText = (LPWSTR)e.name.c_str();
        HTREEITEM hItem = TreeView_InsertItem(g_hDirTree, &tvi);

        if (hItem) {
            // Authoritative storage of the tree item's full path.
            g_TreeMap[hItem] = e.fullPath;

            if (e.isDir)
                SidebarInsertTreeChildren(e.fullPath, hItem, result, childrenByParent);
        }
    }
}

// Called on WM_DIRECTORY_LOADED: drains g_DirLoadQueue and repopulates the TreeView.
void HandleDirectoryLoaded(HWND hwnd, LPARAM /*lParam*/) {
    // lParam is ignored (it was a doorbell). Drain the queue.
    while (true) {
        auto upResult = g_DirLoadQueue.try_pop();
        if (!upResult) break;
        DirLoadResult* result = upResult.get();

    // Guard: stale result if tree no longer exists.
    if (!g_hDirTree || !IsWindow(g_hDirTree)) {
        continue;  // unique_ptr cleans up automatically
    }

    g_TreeRootDir = result->rootDir;
    std::wstring restorePath = !result->selectAfterLoad.empty()
                             ? result->selectAfterLoad
                             : SidebarGetSelectedPath();

    SendMessage(g_hDirTree, WM_SETREDRAW, FALSE, 0);
    TreeView_DeleteAllItems(g_hDirTree);
    // Map entries are owned by the tree; flush them in lock-step.
    g_TreeMap.clear();

    // Insert root label as the first parent item.
    TVINSERTSTRUCT tvRoot = {};
    tvRoot.hParent        = TVI_ROOT;
    tvRoot.hInsertAfter   = TVI_LAST;
    tvRoot.item.mask      = TVIF_TEXT | TVIF_PARAM | TVIF_STATE | TVIF_CHILDREN;
    tvRoot.item.stateMask = TVIS_BOLD;
    tvRoot.item.state     = TVIS_BOLD | TVIS_EXPANDED;
    tvRoot.item.cChildren = result->entries.empty() ? 0 : I_CHILDRENCALLBACK;

    fs::path rootPath(result->rootDir);
    std::wstring rootLabel = rootPath.filename().empty()
                             ? result->rootDir
                             : rootPath.filename().wstring();
    tvRoot.item.pszText = (LPWSTR)rootLabel.c_str();
    tvRoot.item.lParam  = 0;   // path lives in g_TreeMap, not in lParam.
    HTREEITEM hRoot = TreeView_InsertItem(g_hDirTree, &tvRoot);
    if (hRoot) g_TreeMap[hRoot] = result->rootDir;
    // Begin (or restart) real-time directory monitoring for this root so
    // external deletions / renames are reflected in the sidebar without
    // requiring a manual refresh.  The owning window is the main frame —
    // g_hDirTree's parent chain — so we pass GetParent of the tree's parent
    // chain root resolved via GetAncestor(..., GA_ROOT).
    if (hRoot) {
        HWND hOwner = GetAncestor(g_hDirTree, GA_ROOT);
        if (hOwner) FileWatcherStart(hOwner, result->rootDir);
    }

    std::unordered_map<std::wstring, std::vector<size_t>> childrenByParent;
    for (size_t i = 0; i < result->entries.size(); ++i)
        childrenByParent[SidebarPathKey(result->entries[i].parentPath)].push_back(i);

    SidebarInsertTreeChildren(result->rootDir, hRoot, *result, childrenByParent);

    if (hRoot) TreeView_Expand(g_hDirTree, hRoot, TVE_EXPAND);

    SendMessage(g_hDirTree, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_hDirTree, NULL, TRUE);

    if (!g_PendingSelectFile.empty()) {
        restorePath = g_PendingSelectFile;
        g_PendingSelectFile.clear();
    }

    if (!restorePath.empty()) SidebarSelectPath(restorePath);
    if (!result->errorMessage.empty())
        MessageBoxW(hwnd, result->errorMessage.c_str(), L"Folder", MB_OK | MB_ICONWARNING);

    // upResult (unique_ptr) goes out of scope at end of iteration — automatic cleanup.
    } // end while drain loop
}

// Synchronise the sidebar tree to the active tab's directory.
// filePath        - if non-empty, also request auto-highlight of that item.
// defineWorkspace - true only for explicit workspace-defining actions.
// Internal navigation never re-roots the tree; it only selects/expands paths
// already contained beneath g_TreeRootDir.
void SidebarSyncToActiveTab(HWND hMainWnd, const std::wstring& filePath, bool defineWorkspace) {
    EditorTab* tab = GetActiveTab();
    if (!tab || tab->sFilePath.empty()) return;

    const std::wstring& fp = filePath.empty() ? tab->sFilePath : filePath;
    std::wstring dir = fs::path(fp).parent_path().wstring();
    if (dir.empty()) return;

    if (g_TreeRootDir.empty() || defineWorkspace) {
        if (!fp.empty()) g_PendingSelectFile = fp;
        SidebarLoadDirectory(hMainWnd, dir, true, fp);
        return;
    }

    if (SidebarPathIsUnderRoot(fp, g_TreeRootDir)) {
        if (!fp.empty()) SidebarSelectPath(fp);
        return;
    }
}

void SidebarCreateFolder(HWND hMainWnd) {
    std::wstring rootDir = g_TreeRootDir;
    if (rootDir.empty()) {
        EditorTab* tab = GetActiveTab();
        if (tab && !tab->sFilePath.empty())
            rootDir = fs::path(tab->sFilePath).parent_path().wstring();
    }

    if (rootDir.empty()) {
        MessageBoxW(hMainWnd, L"Open or save a file first so the sidebar has a folder to use.",
                    L"Create Folder", MB_OK | MB_ICONINFORMATION);
        return;
    }

    std::wstring folderName;
    if (!PromptForFolderName(hMainWnd, folderName)) return;

    std::wstring createParentDir = rootDir;
    std::wstring selectedPath = SidebarGetSelectedPath();
    if (!selectedPath.empty() && SidebarPathIsUnderRoot(selectedPath, rootDir)) {
        std::error_code ec;
        if (fs::is_directory(selectedPath, ec)) {
            createParentDir = selectedPath;
        } else {
            std::wstring selectedParent = fs::path(selectedPath).parent_path().wstring();
            if (!selectedParent.empty() && SidebarPathIsUnderRoot(selectedParent, rootDir))
                createParentDir = selectedParent;
        }
    }

    SidebarLoadDirectory(hMainWnd, rootDir, true, L"", folderName, createParentDir);
}

// Open a file from the sidebar into the editor (or switch to an existing tab).
void SidebarOpenFile(HWND hMainWnd, const std::wstring& filePath) {
    if (filePath.empty()) return;

    // ----------------------------------------------------------------
    // 1. Intelligence: Strict Duplicate Check
    // ----------------------------------------------------------------
    for (size_t i = 0; i < g_Tabs.size(); ++i) {
        if (g_Tabs[i] && _wcsicmp(g_Tabs[i]->sFilePath.c_str(), filePath.c_str()) == 0) {
            // v21: if a worker thread is already loading THIS file into
            // THIS tab, do NOT fall through to a second BeginAsyncFileLoadEx.
            // Just switch to the reserved (hourglass) tab. This kills the
            // duplicate "⏳ filename" tab that appeared on a fast double-click
            // or when the sidebar fired the same path twice.
            if (g_Tabs[i]->bAsyncLoading) {
                const int curSel = TabCtrl_GetCurSel(hGlobalTabCtrl);
                if (curSel != static_cast<int>(i)) {
                    TabCtrl_SetCurSel(hGlobalTabCtrl, static_cast<int>(i));
                    NMHDR nm = { hGlobalTabCtrl, (UINT_PTR)IDC_MAIN_TAB, TCN_SELCHANGE };
                    SendMessage(hMainWnd, WM_NOTIFY, (WPARAM)IDC_MAIN_TAB, (LPARAM)&nm);
                }
                return; // load already in flight — nothing else to do
            }

            // v4.17 fix: if this tab was RAM-purged it still owns sFilePath but its
            // PieceTable / EDIT control are empty.  Switch to it AND fall through
            // to the disk-load path below so the same tab gets refilled from disk.
            if (g_Tabs[i]->bPurgedNeedsReload) {
                const int curSel = TabCtrl_GetCurSel(hGlobalTabCtrl);
                if (curSel != static_cast<int>(i)) {
                    TabCtrl_SetCurSel(hGlobalTabCtrl, static_cast<int>(i));
                    NMHDR nm = { hGlobalTabCtrl, (UINT_PTR)IDC_MAIN_TAB, TCN_SELCHANGE };
                    SendMessage(hMainWnd, WM_NOTIFY, (WPARAM)IDC_MAIN_TAB, (LPARAM)&nm);
                }
                break; // do NOT return — fall through to disk-load + repopulate
            }

            const int currentSel = TabCtrl_GetCurSel(hGlobalTabCtrl);
            if (currentSel != static_cast<int>(i)) {
                TabCtrl_SetCurSel(hGlobalTabCtrl, static_cast<int>(i));

                // Manually trigger the selection change to restore the pinned workspace
                NMHDR nm = { hGlobalTabCtrl, (UINT_PTR)IDC_MAIN_TAB, TCN_SELCHANGE };
                SendMessage(hMainWnd, WM_NOTIFY, (WPARAM)IDC_MAIN_TAB, (LPARAM)&nm);
            }
            return; // File is already handled
        }
    }

    // ----------------------------------------------------------------
    // 2. Determine workspace anchor (cheap, UI-thread)
    // ----------------------------------------------------------------
    std::wstring anchorRoot = g_CurrentSidebarRoot;
    std::error_code ec;
    if (anchorRoot.empty() || !fs::exists(anchorRoot, ec)) {
        anchorRoot = fs::path(filePath).parent_path().wstring();
    }

    // ----------------------------------------------------------------
    // 3. Probe file size + safety cap (cheap stat call)
    // ----------------------------------------------------------------
    long long fileSize = 0;
    {
        WIN32_FILE_ATTRIBUTE_DATA fad{};
        if (!GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &fad)) {
            DWORD dwErr = GetLastError();
            std::wstring msg = L"Cannot open file. Error code: " + std::to_wstring(dwErr);
            MessageBoxW(hMainWnd, msg.c_str(), L"System Access Error", MB_OK | MB_ICONERROR);
            return;
        }
        ULARGE_INTEGER u; u.HighPart = fad.nFileSizeHigh; u.LowPart = fad.nFileSizeLow;
        fileSize = (long long)u.QuadPart;
        if (fileSize > 100LL * 1024 * 1024) {
            MessageBoxW(hMainWnd, L"File is too large for the editor (Max 100MB).",
                        L"Safety Limit", MB_OK | MB_ICONWARNING);
            return;
        }
    }

    // ----------------------------------------------------------------
    // 4. Async path — keep the UI thread responsive on large files.
    //    Threshold: anything >= 64 KB goes through the worker so syntax
    //    checks, scrolling, and typing in other tabs stay smooth.
    // ----------------------------------------------------------------
    EditorTab* active = GetActiveTab();
    bool reusePurged = active && active->bPurgedNeedsReload &&
                       _wcsicmp(active->sFilePath.c_str(), filePath.c_str()) == 0;
    bool reuseEmpty  = active && !active->bModified && active->sFilePath.empty() &&
                       (GetWindowTextLength(active->hEdit) == 0);

    if (fileSize >= 64LL * 1024) {
        // Decide which tab the worker's result will populate.  We must reserve
        // it NOW so a second click doesn't spawn duplicates while the worker
        // is still reading.  We piggy-back on WM_FILE_LOAD_COMPLETE's existing
        // reuse logic (empty active tab) by either:
        //   • leaving the active tab empty (it will be reused), or
        //   • pre-creating a tab and stamping sFilePath so the duplicate-check
        //     at the top of SidebarOpenFile catches a second click.
        EditorTab* target = nullptr;
        if (reusePurged || reuseEmpty) {
            target = active;
        } else {
            CreateNewTab(hMainWnd);
            target = GetActiveTab();
        }
        if (target) {
            target->sFilePath        = filePath;
            target->sFileName        = fs::path(filePath).filename().wstring();
            target->sWorkspaceRoot   = anchorRoot;
            target->bModified        = false;
            // v21: use the dedicated in-flight flag instead of overloading
            // bPurgedNeedsReload. The duplicate-check at the top of
            // SidebarOpenFile now switches to (and returns on) any tab with
            // bAsyncLoading==true, so a second click on the same sidebar
            // entry no longer creates a second hourglass tab.
            target->bAsyncLoading    = true;
            // Preserve purge-reload semantics only when this tab was actually
            // a purged tab being refilled (reusePurged==true).
            if (reusePurged) target->bPurgedNeedsReload = true;
            // Show "Loading..." caption inside the editor itself for instant feedback.
            {
                RestoreGuard guard(&target->isRestoring);
                SetWindowTextW(target->hEdit, L"");
            }
            TCITEMW tie = { 0 };
            tie.mask    = TCIF_TEXT;
            std::wstring loadingCaption = L"\u23F3 " + target->sFileName;
            tie.pszText = const_cast<LPWSTR>(loadingCaption.c_str());
            TabCtrl_SetItem(hGlobalTabCtrl, g_ActiveTabIndex, &tie);
        }

        auto payload = std::make_unique<FileLoadPayload>();
        payload->hMainWnd       = hMainWnd;
        payload->sFilePath      = filePath;
        payload->sFileName      = fs::path(filePath).filename().wstring();
        payload->sWorkspaceHint = anchorRoot;
        payload->sWorkspaceRoot = anchorRoot;
        payload->bFromSidebar   = true;
        payload->llFileSize     = fileSize;
        BeginAsyncFileLoadEx(std::move(payload));

        // Recent-folders + UI bookkeeping happen now; the worker only refills text.
        if (!anchorRoot.empty()) {
            auto it = std::remove(g_RecentFolders.begin(), g_RecentFolders.end(), anchorRoot);
            g_RecentFolders.erase(it, g_RecentFolders.end());
            g_RecentFolders.insert(g_RecentFolders.begin(), anchorRoot);
            if (g_RecentFolders.size() > MAX_RECENT_FOLDERS) g_RecentFolders.pop_back();
            UpdateRecentFoldersMenu(hMainWnd);
        }
        return;
    }

    // ----------------------------------------------------------------
    // 4b. Sync path — small files only (< 64 KB).
    // ----------------------------------------------------------------
    std::wstring contentBuffer;
    try {
        FILE* fp = _wfopen(filePath.c_str(), L"rb");
        if (!fp) {
            DWORD dwErr = GetLastError();
            std::wstring msg = L"Cannot open file. Error code: " + std::to_wstring(dwErr);
            MessageBoxW(hMainWnd, msg.c_str(), L"System Access Error", MB_OK | MB_ICONERROR);
            return;
        }
        if (fileSize > 0) {
            std::vector<char> rawBytes(static_cast<size_t>(fileSize));
            size_t bytesRead = fread(rawBytes.data(), 1, rawBytes.size(), fp);
            fclose(fp);
            if (bytesRead > 0) {
                int wn = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, rawBytes.data(), (int)bytesRead, NULL, 0);
                if (wn > 0) {
                    contentBuffer.resize(wn);
                    MultiByteToWideChar(CP_UTF8, 0, rawBytes.data(), (int)bytesRead, &contentBuffer[0], wn);
                } else {
                    wn = MultiByteToWideChar(CP_ACP, 0, rawBytes.data(), (int)bytesRead, NULL, 0);
                    if (wn > 0) {
                        contentBuffer.resize(wn);
                        MultiByteToWideChar(CP_ACP, 0, rawBytes.data(), (int)bytesRead, &contentBuffer[0], wn);
                    }
                }
                std::wstring normalized;
                normalized.reserve(contentBuffer.size() + (contentBuffer.size() / 10));
                for (wchar_t c : contentBuffer) {
                    if (c == L'\n' && (normalized.empty() || normalized.back() != L'\r'))
                        normalized += L'\r';
                    normalized += c;
                }
                contentBuffer = std::move(normalized);
            }
        } else {
            fclose(fp);
        }
    } catch (...) {
        MessageBoxW(hMainWnd, L"An unexpected filesystem exception occurred.", L"Critical", MB_OK | MB_ICONERROR);
        return;
    }

    bool reuseTab = reusePurged || reuseEmpty;
    if (!reuseTab) CreateNewTab(hMainWnd);
    EditorTab* tab = GetActiveTab();
    if (!tab) return;

    {
        RestoreGuard guard(&tab->isRestoring);
        SetWindowTextW(tab->hEdit, contentBuffer.c_str());
    }

    tab->sFilePath          = filePath;
    tab->sFileName          = fs::path(filePath).filename().wstring();
    tab->sWorkspaceRoot     = anchorRoot;
    tab->bModified          = false;
    tab->pt.LoadOriginal(contentBuffer);
    tab->ptDirty            = false;
    tab->bPurgedNeedsReload = false;

    // UI Tab Label update
    TCITEMW tie = { 0 };
    tie.mask = TCIF_TEXT;
    tie.pszText = const_cast<LPWSTR>(tab->sFileName.c_str());
    TabCtrl_SetItem(hGlobalTabCtrl, g_ActiveTabIndex, &tie);

    // ----------------------------------------------------------------
    // 5. Intelligent Global Sync
    // ----------------------------------------------------------------
    if (!anchorRoot.empty()) {
        auto it = std::remove(g_RecentFolders.begin(), g_RecentFolders.end(), anchorRoot);
        g_RecentFolders.erase(it, g_RecentFolders.end());
        g_RecentFolders.insert(g_RecentFolders.begin(), anchorRoot);
        if (g_RecentFolders.size() > MAX_RECENT_FOLDERS) g_RecentFolders.pop_back();
        UpdateRecentFoldersMenu(hMainWnd);
    }

    // Final UI Refresh
    UpdateTitle(hMainWnd);
    UpdateGutter(tab->hEdit, tab->hGutter);
    UpdateLineCount(tab->hEdit, hGlobalLineCount);
    UpdateColInfo(tab->hEdit);
    UpdatePieceCount(tab);

    if (tab->hGutter && IsWindow(tab->hGutter)) {
        InvalidateRect(tab->hGutter, NULL, TRUE);
    }

    // Force focus to the edit control
    SetFocus(tab->hEdit);

    // Snap the Sidebar back to the anchor root
    SidebarLoadDirectory(hMainWnd, tab->sWorkspaceRoot, true, filePath);
}

// Cleanup: legacy free routine.
//
// Path payloads now live in g_TreeMap rather than in heap-allocated
// std::wstring* objects pinned to lParam, so there is nothing to
// individually free here.  The function is retained as a no-op for ABI
// compatibility with existing call sites; map clearing is performed by the
// caller (RemoveTab / WM_DESTROY / HandleDirectoryLoaded).
static void SidebarFreeTreeItemData(HWND /*hTree*/, HTREEITEM /*hItem*/) {
    // Intentionally empty.  See block comment above.
}

void CreateNewTab(HWND hwndParent) {
    // v4.44 O1: allocate as unique_ptr from the start so failure paths free
    // automatically.  We hand out a non-owning raw pointer (`tab`) for the
    // setup code; ownership stays in `owner` until we move it into g_Tabs.
    auto       owner = std::make_unique<EditorTab>();
    EditorTab* tab   = owner.get();

    RECT rc;
    GetClientRect(hwndParent, &rc);

    // Sidebar [0, g_sidebarWidth) + splitter [g_sidebarWidth, +SPLITTER_WIDTH) + gutter here.
    // WM_SIZE recalculates exact positions immediately; these are just non-zero placeholders.
    int initEditorLeft = (g_sidebarVisible ? g_sidebarWidth : 0) + SPLITTER_WIDTH;
    tab->hGutter = CreateWindowEx(0, L"STATIC", L"",
        WS_CHILD | SS_OWNERDRAW | WS_CLIPSIBLINGS,
        initEditorLeft, 32, 50, rc.bottom - 107,
        hwndParent, (HMENU)IDC_GUTTER, GetModuleHandle(NULL), NULL);

    if (!tab->hGutter) { return; /* unique_ptr frees */ }

    SetWindowLongPtr(tab->hGutter, GWLP_USERDATA, (LONG_PTR)tab);
    if (!OldGutterProc)
        OldGutterProc = (WNDPROC)SetWindowLongPtr(tab->hGutter, GWLP_WNDPROC,
                                                    (LONG_PTR)GutterSubclassProc);
    else
        SetWindowLongPtr(tab->hGutter, GWLP_WNDPROC, (LONG_PTR)GutterSubclassProc);

    // v4.32 perf NOTE: WS_EX_COMPOSITED was tried here for double-buffered
    // painting but caused the classic EDIT control to render a blank client
    // area on some systems (its internal WM_PAINT does not cooperate with
    // the desktop compositor's bottom-up buffer). Reverted. The EN_CHANGE
    // coalescing in WindowProc still gives us the typing-lag win on its own.
    tab->hEdit = CreateWindowEx(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VSCROLL | WS_HSCROLL |
        ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL |
        ES_WANTRETURN | ES_NOHIDESEL | WS_CLIPSIBLINGS,
        initEditorLeft + 50, 32,
        rc.right - (initEditorLeft + 50), rc.bottom - 107,
        hwndParent, (HMENU)IDC_MAIN_EDIT, GetModuleHandle(NULL), NULL);

    if (!tab->hEdit) {
        DestroyWindow(tab->hGutter);
        return; /* unique_ptr frees */
    }

    SendMessage(tab->hEdit,   WM_SETFONT, (WPARAM)hEditorFont, TRUE);
    SendMessage(tab->hGutter, WM_SETFONT, (WPARAM)hEditorFont, TRUE);
    SendMessage(tab->hEdit,   EM_SETLIMITTEXT, 0, 0);

    SetWindowLongPtr(tab->hEdit, GWLP_USERDATA, (LONG_PTR)tab);
    if (!OldEditProc)
        OldEditProc = (WNDPROC)SetWindowLongPtr(tab->hEdit, GWLP_WNDPROC,
                                                  (LONG_PTR)EditSubclassProc);
    else
        SetWindowLongPtr(tab->hEdit, GWLP_WNDPROC, (LONG_PTR)EditSubclassProc);

    // v4.44 O1: ownership transfer into g_Tabs.  After this line `owner`
    // is empty; g_Tabs is the sole owner of the EditorTab.
    TF_RegisterTab(tab);   // v4.43 R1: side-table for stable-ID lookups
    g_Tabs.push_back(std::move(owner));

    TCITEM tie;
    tie.mask    = TCIF_TEXT | TCIF_PARAM;
    tie.pszText = (LPWSTR)tab->sFileName.c_str();
    tie.lParam  = (LPARAM)tab;
    int newIndex = TabCtrl_InsertItem(hGlobalTabCtrl, (int)g_Tabs.size() - 1, &tie);
    if (newIndex == -1) newIndex = (int)g_Tabs.size() - 1;

    SwitchToTab(newIndex);
}

void SwitchToTab(int index) {
    if (index < 0 || index >= (int)g_Tabs.size()) return;
    g_ActiveTabIndex = index;
    TabCtrl_SetCurSel(hGlobalTabCtrl, index);

    for (int i = 0; i < (int)g_Tabs.size(); i++) {
        // v4.44: unique_ptr supports operator-> directly
        ShowWindow(g_Tabs[i]->hEdit,   (i == index) ? SW_SHOW : SW_HIDE);
        ShowWindow(g_Tabs[i]->hGutter, (i == index) ? SW_SHOW : SW_HIDE);
    }

    if (g_Tabs[index]->hEdit && IsWindow(g_Tabs[index]->hEdit)) {
        SetFocus(g_Tabs[index]->hEdit);
        UpdateGutter(g_Tabs[index]->hEdit, g_Tabs[index]->hGutter);
        UpdatePieceCount(g_Tabs[index].get());
        UpdateTitle(GetParent(hGlobalTabCtrl));
    }

    // Bi-directional sync: if the newly-active tab's file is in a different
    // directory than what the tree currently shows, reload the tree.
    HWND hMain = GetParent(hGlobalTabCtrl);
    if (hMain) SidebarSyncToActiveTab(hMain);
}

// =============================================================================
//  FILE OPERATIONS
// =============================================================================
void DoFileOpen(HWND hwnd) {
    OPENFILENAMEW ofn;
    wchar_t szFile[MAX_PATH]      = { 0 };
    wchar_t szFileTitle[MAX_PATH] = { 0 };
    wchar_t initDir[MAX_PATH]     = { 0 };

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize    = sizeof(ofn);
    ofn.hwndOwner      = hwnd;
    ofn.lpstrFile      = szFile;
    ofn.nMaxFile       = MAX_PATH;
    ofn.lpstrFileTitle = szFileTitle;
    ofn.nMaxFileTitle  = MAX_PATH;
    ofn.lpstrFilter    =
        L"All Files (*.*)\0*.*\0"
        L"Python Files (*.py)\0*.py\0"
        L"C++ Files (*.cpp)\0*.cpp\0";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    if (!g_NextOpenDir.empty()) {
        wcscpy_s(initDir, MAX_PATH, g_NextOpenDir.c_str());
        ofn.lpstrInitialDir = initDir;
    }

    if (GetOpenFileNameW(&ofn)) {
        // Snapshot the workspace hint NOW (UI thread); the thread proc must not touch globals.
        std::wstring workspaceHint = g_NextOpenDir;

        // Update Recent Folders synchronously — cheap, and safer to do on UI thread.
        if (ofn.nFileOffset > 0) {
            std::wstring folderPath = std::wstring(ofn.lpstrFile).substr(0, ofn.nFileOffset);
            g_RecentFolders.erase(
                std::remove(g_RecentFolders.begin(), g_RecentFolders.end(), folderPath),
                g_RecentFolders.end());
            g_RecentFolders.insert(g_RecentFolders.begin(), folderPath);
            if (g_RecentFolders.size() > MAX_RECENT_FOLDERS) g_RecentFolders.pop_back();
            UpdateRecentFoldersMenu(hwnd);
        }

        // Hand off the heavy lifting to the background worker.
        BeginAsyncFileLoad(hwnd, ofn.lpstrFile, workspaceHint);
    }
    g_NextOpenDir = L"";
}


void ShowSaveSuccess(HWND hwnd, const wstring& fileName, const wstring& filePath) {
    wstring msg = L"\"" + fileName + L"\" saved to:\n" + filePath;
    MessageBoxW(hwnd, msg.c_str(), L"Save Successful", MB_OK | MB_ICONINFORMATION);
}

bool DoFileSaveAs(HWND hwnd) {
    EditorTab* tab = GetActiveTab();
    if (!tab) return false;

    OPENFILENAMEW ofn;
    wchar_t szFile[MAX_PATH]      = { 0 };
    wchar_t szFileTitle[MAX_PATH] = { 0 };

    if (!tab->sFilePath.empty())
        wcscpy_s(szFile, MAX_PATH, tab->sFilePath.c_str());

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize    = sizeof(ofn);
    ofn.hwndOwner      = hwnd;
    ofn.lpstrFile      = szFile;
    ofn.nMaxFile       = MAX_PATH;
    ofn.lpstrFileTitle = szFileTitle;
    ofn.nMaxFileTitle  = MAX_PATH;
    ofn.lpstrFilter    =
        L"All Files (*.*)\0*.*\0"
        L"Python Files (*.py)\0*.py\0"
        L"C++ Files (*.cpp)\0*.cpp\0";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;

    if (GetSaveFileNameW(&ofn)) {
        tab->sFilePath = ofn.lpstrFile;
        tab->sFileName = ofn.lpstrFileTitle;

        if (ofn.nFileOffset > 0) {
            std::wstring folderPath = tab->sFilePath.substr(0, ofn.nFileOffset);
            g_RecentFolders.erase(
                std::remove(g_RecentFolders.begin(), g_RecentFolders.end(), folderPath),
                g_RecentFolders.end());
            g_RecentFolders.insert(g_RecentFolders.begin(), folderPath);
            if (g_RecentFolders.size() > MAX_RECENT_FOLDERS) g_RecentFolders.pop_back();
            UpdateRecentFoldersMenu(hwnd);
        }

        SaveEntry entry = { tab->sFileName, tab->sFilePath };
        g_SaveLog.erase(
            std::remove_if(g_SaveLog.begin(), g_SaveLog.end(),
                [&](const SaveEntry& e) { return e.filePath == entry.filePath; }),
            g_SaveLog.end());
        g_SaveLog.insert(g_SaveLog.begin(), entry);
        if (g_SaveLog.size() > MAX_SAVE_LOG) g_SaveLog.pop_back();

        if (!WriteFileContent(tab->sFilePath.c_str(), tab)) return false;
        tab->bModified = false;

        TCITEM tie;
        tie.mask    = TCIF_TEXT;
        tie.pszText = (LPWSTR)tab->sFileName.c_str();
        TabCtrl_SetItem(hGlobalTabCtrl, g_ActiveTabIndex, &tie);

        UpdateTitle(hwnd);
        SidebarRefreshAfterDiskWrite(hwnd, tab->sFilePath);
        ShowSaveSuccess(hwnd, tab->sFileName, tab->sFilePath);
        return true;
    }
    return false;
}

bool DoFileSave(HWND hwnd) {
    EditorTab* tab = GetActiveTab();
    if (!tab) return false;

    if (tab->sFilePath.empty()) {
        return DoFileSaveAs(hwnd);
    } else {
        SaveEntry entry = { tab->sFileName, tab->sFilePath };
        g_SaveLog.erase(
            std::remove_if(g_SaveLog.begin(), g_SaveLog.end(),
                [&](const SaveEntry& e) { return e.filePath == entry.filePath; }),
            g_SaveLog.end());
        g_SaveLog.insert(g_SaveLog.begin(), entry);
        if (g_SaveLog.size() > MAX_SAVE_LOG) g_SaveLog.pop_back();

        if (!WriteFileContent(tab->sFilePath.c_str(), tab)) return false;
        tab->bModified = false;
        UpdateTitle(hwnd);
        SidebarRefreshAfterDiskWrite(hwnd, tab->sFilePath);
        ShowSaveSuccess(hwnd, tab->sFileName, tab->sFilePath);
        return true;
    }
}

// =============================================================================
//  MAIN WINDOW PROCEDURE
// =============================================================================
// =============================================================================
//  DIRECTORY WATCHER — v4.15 — intelligent recursive filesystem monitoring
//
//  Architecture:
//    • WatcherContext (local struct in FileWatcherThreadBody) bundles the
//      OVERLAPPED object, the directory HANDLE, and a 64 KiB BYTE buffer.
//      Its lifetime == the watcher thread's lifetime — no dangling state.
//    • ReadDirectoryChangesW runs with bWatchSubtree = TRUE and a composite
//      filter:  FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME
//             | FILE_NOTIFY_CHANGE_LAST_WRITE
//    • FILE_NOTIFY_INFORMATION linked-list is parsed per action:
//
//        REMOVED / RENAMED_OLD_NAME
//            → targeted O(depth) deletion via g_FileRemovedQueue +
//              WM_FILE_REMOVED.  Existing HandleFileRemovedMessage path,
//              fully intact from v4.11.
//
//        ADDED / RENAMED_NEW_NAME
//            → coalesced full sidebar rescan via g_SidebarRefreshPending
//              compare_exchange + WM_SIDEBAR_REFRESH.  A burst of N additions
//              (build output, git checkout) posts exactly ONE doorbell.
//
//        MODIFIED (LAST_WRITE)
//            → discarded. Content changes do not alter tree structure.
//
//        bytes == 0 (kernel buffer overflow)
//            → treated as ADDED (conservative correctness over performance).
//
//    • Shutdown: WM_DESTROY signals g_FileWatcher.hShutdown + CancelIoEx;
//      WaitForMultipleObjects returns immediately; the OVERLAPPED is drained;
//      g_ThreadMgr.shutdownAll() joins the std::thread.  The watcher cannot
//      outlive the sidebar it observes.
//    • Path normalisation mirrors SidebarPathKey() so g_TreeMap lookups hit.
//
//  Thread model:
//    • Watcher thread: blocks in WaitForMultipleObjects; touches no UI state.
//    • UI thread:      owns g_TreeMap, g_hDirTree, all TreeView_* calls.
//    • Cross-thread channels:
//        g_FileRemovedQueue  (ThreadSafeQueue<wstring>) + WM_FILE_REMOVED
//        g_SidebarRefreshPending (atomic<bool>)         + WM_SIDEBAR_REFRESH
//
//  Restart policy:
//    • FileWatcherStart() is idempotent — stops any prior watcher, then
//      spawns a fresh thread via g_ThreadMgr.  Called from HandleDirectoryLoaded
//      each time the sidebar root changes.
// =============================================================================

// ══════════════════════════════════════════════════════════════════════════════
//  MODULE: File system watcher  (v4.15 — WatcherContext, expanded filter,
//          per-action dispatch, coalesced WM_SIDEBAR_REFRESH)
// ══════════════════════════════════════════════════════════════════════════════

// FileWatcherState no longer holds a Win32 HANDLE hThread field.
// The thread is owned by g_ThreadMgr (std::thread, joined on shutdownAll).
// We keep hDir and hShutdown for the CancelIoEx + OVERLAPPED cooperative stop.
struct FileWatcherState {
    HANDLE             hDir      = INVALID_HANDLE_VALUE;
    HANDLE             hShutdown = NULL;        // manual-reset event; signals the watcher to stop
    std::wstring       rootDir;                 // canonicalised, no trailing slash
    std::atomic<bool>  running   { false };     // true while the thread body executes
};

static FileWatcherState g_FileWatcher;

// Forward decl — SidebarPathKey is defined earlier in the file and used by
// the existing tree map.  We re-declare its signature here for clarity; the
// linker resolves to the original definition.
extern std::wstring SidebarPathKey(const std::wstring& p);

// Strip a single trailing '\\' or '/' (but not a drive-root like "C:\").
static std::wstring FW_StripTrailingSep(const std::wstring& p) {
    if (p.size() > 3 && (p.back() == L'\\' || p.back() == L'/'))
        return p.substr(0, p.size() - 1);
    return p;
}

// Combine root + relative-from-notification into a single absolute path,
// using the same separator convention SidebarPathKey expects.
static std::wstring FW_JoinAbsolute(const std::wstring& root,
                                    const wchar_t* relBuf, DWORD relLenBytes) {
    std::wstring rel(relBuf, relLenBytes / sizeof(wchar_t));
    for (auto& c : rel) if (c == L'/') c = L'\\';
    std::wstring full = FW_StripTrailingSep(root);
    full.reserve(full.size() + 1 + rel.size());
    full.append(L"\\");
    full.append(rel);
    return full;
}

// Background thread body — v4.15 revision.
//
// v4.11: converted from _beginthreadex to std::thread; g_FileRemovedQueue
//        doorbell pattern replaces raw lParam heap pointer.
// v4.15 changes:
//   • WatcherContext struct (local to this function) owns the OVERLAPPED and
//     the 64 KiB stack-local buffer.  Lifetime == thread lifetime, making
//     any dangling-handle bug impossible by construction.
//   • Filter expanded to FILE_NAME | DIR_NAME | LAST_WRITE.
//   • Per-action dispatch:
//       REMOVED / RENAMED_OLD → targeted g_FileRemovedQueue + WM_FILE_REMOVED
//       ADDED   / RENAMED_NEW → coalesced WM_SIDEBAR_REFRESH (compare_exchange)
//       MODIFIED              → discarded (content change; tree unchanged)
//   • bytes == 0 (kernel buffer overflow) → conservative full rescan.
static void FileWatcherThreadBody(HWND hwndOwner) {
    // ── WatcherContext ────────────────────────────────────────────────────────
    // Bundles OVERLAPPED + buffer in one place. Defined locally so its
    // lifetime equals this thread's — no dangling handle possible.
    struct WatcherContext {
        OVERLAPPED ov;
        BYTE       buf[64 * 1024]; // 64 KiB: zero data loss on burst events
        WatcherContext() noexcept : ov{} { std::memset(buf, 0, sizeof(buf)); }
        WatcherContext(const WatcherContext&)            = delete;
        WatcherContext& operator=(const WatcherContext&) = delete;
    };

    std::wstring watchRoot = FW_StripTrailingSep(
        !g_FileWatcher.rootDir.empty() ? g_FileWatcher.rootDir : g_TreeRootDir);
    if (watchRoot.empty() || !g_appRunning.load()) {
        g_FileWatcher.running.store(false);
        return;
    }

    g_FileWatcher.hDir = CreateFileW(
        watchRoot.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        NULL);
    if (g_FileWatcher.hDir == INVALID_HANDLE_VALUE) {
        g_FileWatcher.running.store(false);
        return;
    }

    WatcherContext ctx;
    ctx.ov.hEvent = CreateEventW(NULL, TRUE /*manual reset*/, FALSE, NULL);
    if (!ctx.ov.hEvent) {
        CloseHandle(g_FileWatcher.hDir);
        g_FileWatcher.hDir = INVALID_HANDLE_VALUE;
        g_FileWatcher.running.store(false);
        return;
    }

    // ── Notification filter ───────────────────────────────────────────────────
    // FILE_NOTIFY_CHANGE_FILE_NAME  — file create, delete, rename
    // FILE_NOTIFY_CHANGE_DIR_NAME   — subdirectory create, delete, rename
    // FILE_NOTIFY_CHANGE_LAST_WRITE — file content written (save events)
    //
    // LAST_WRITE is included so every external editor save is captured.
    // The handler discards FILE_ACTION_MODIFIED so content changes never
    // trigger a sidebar rescan (tree structure is unaffected by file saves).
    constexpr DWORD kFilter =
        FILE_NOTIFY_CHANGE_FILE_NAME |
        FILE_NOTIFY_CHANGE_DIR_NAME  |
        FILE_NOTIFY_CHANGE_LAST_WRITE;

    HANDLE waitHandles[2] = { ctx.ov.hEvent, g_FileWatcher.hShutdown };

    while (g_appRunning.load() &&
           WaitForSingleObject(g_FileWatcher.hShutdown, 0) != WAIT_OBJECT_0) {

        ResetEvent(ctx.ov.hEvent);
        DWORD bytesReturnedSync = 0;
        BOOL ok = ReadDirectoryChangesW(
            g_FileWatcher.hDir,
            ctx.buf,
            sizeof(ctx.buf),
            TRUE,               // bWatchSubtree — full recursive monitoring
            kFilter,
            &bytesReturnedSync,
            &ctx.ov,
            NULL);              // no APC — we use the manual-reset event handle

        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_OPERATION_ABORTED) break;
            break;
        }

        DWORD wr = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
        if (wr == WAIT_OBJECT_0 + 1) {
            // Shutdown event — drain the pending overlapped I/O before exiting
            // so the OVERLAPPED is never referenced after the thread returns.
            CancelIoEx(g_FileWatcher.hDir, &ctx.ov);
            DWORD drained = 0;
            GetOverlappedResult(g_FileWatcher.hDir, &ctx.ov, &drained, TRUE);
            break;
        }
        if (wr != WAIT_OBJECT_0) break;

        DWORD bytes = 0;
        if (!GetOverlappedResult(g_FileWatcher.hDir, &ctx.ov, &bytes, FALSE)) {
            DWORD err = GetLastError();
            if (err == ERROR_OPERATION_ABORTED) break;
            continue;
        }

        // bytes == 0: the kernel's internal notification buffer overflowed —
        // too many changes arrived before we read them.  Treat this as a
        // structural add so the sidebar is conservatively refreshed.
        if (bytes == 0) {
            bool expected = false;
            if (g_SidebarRefreshPending.compare_exchange_strong(expected, true))
                PostMessageW(hwndOwner, WM_SIDEBAR_REFRESH, 0, 0);
            continue;
        }

        // ── Parse FILE_NOTIFY_INFORMATION linked list ─────────────────────────
        // Per-action dispatch keeps each event on its cheapest possible path:
        //
        //   REMOVED / RENAMED_OLD → targeted item deletion (g_FileRemovedQueue)
        //   ADDED   / RENAMED_NEW → coalesced full rescan (WM_SIDEBAR_REFRESH)
        //   MODIFIED              → ignored (content change; structure unchanged)
        bool needsRefresh = false;
        const BYTE* p = ctx.buf;
        for (;;) {
            if (!g_appRunning.load()) break;
            const FILE_NOTIFY_INFORMATION* fni =
                reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(p);

            switch (fni->Action) {
            case FILE_ACTION_REMOVED:
            case FILE_ACTION_RENAMED_OLD_NAME: {
                // Fast path: push the absolute path and ring the targeted doorbell.
                // The UI thread removes just the matching tree item — O(depth),
                // not a full rescan.
                std::wstring abs = FW_JoinAbsolute(
                    watchRoot, fni->FileName, fni->FileNameLength);
                if (g_FileRemovedQueue.push(std::move(abs)))
                    PostMessageW(hwndOwner, WM_FILE_REMOVED, 0, 0);
                break;
            }
            case FILE_ACTION_ADDED:
            case FILE_ACTION_RENAMED_NEW_NAME:
                // New entry appeared — flag a full sidebar rescan so the tree
                // reflects the added file or directory.
                needsRefresh = true;
                break;
            // FILE_ACTION_MODIFIED: content change only — sidebar unchanged.
            default:
                break;
            }

            if (fni->NextEntryOffset == 0) break;
            p += fni->NextEntryOffset;
        }

        // ── Coalesced WM_SIDEBAR_REFRESH ──────────────────────────────────────
        // compare_exchange guarantees exactly ONE doorbell is in the Win32
        // message queue at any time.  Rapid bursts (build systems emitting
        // dozens of ADDED events per second) are absorbed: only the first
        // triggers a PostMessage; subsequent ones see the flag already true and
        // skip the Post.  The handler resets the flag before calling
        // SidebarLoadDirectory so the very next structural change after the
        // rescan begins will post a fresh doorbell without any gap.
        if (needsRefresh) {
            bool expected = false;
            if (g_SidebarRefreshPending.compare_exchange_strong(expected, true))
                PostMessageW(hwndOwner, WM_SIDEBAR_REFRESH, 0, 0);
        }
    }

    CloseHandle(ctx.ov.hEvent);
    g_FileWatcher.running.store(false);
}

// Stop any running watcher, blocking until the thread exits.  Safe to call
// from the UI thread, and safe to call repeatedly (idempotent).
//
// v4.11: hThread (Win32 HANDLE) is gone — the thread is joined by
// g_ThreadMgr.shutdownAll().  FileWatcherStop() only signals hShutdown and
// issues CancelIoEx so the thread body's WaitForMultipleObjects returns
// immediately.  The join happens inside shutdownAll().
static void FileWatcherStop() {
    // v4.22: even on the "nothing running" branch make sure the shutdown
    // event handle is reclaimed if it was created but never armed.
    if (!g_FileWatcher.running.load() &&
        g_FileWatcher.hDir == INVALID_HANDLE_VALUE) {
        if (g_FileWatcher.hShutdown) {
            CloseHandle(g_FileWatcher.hShutdown);
            g_FileWatcher.hShutdown = NULL;
        }
        return;
    }

    // Signal the thread to exit.
    if (g_FileWatcher.hShutdown) SetEvent(g_FileWatcher.hShutdown);
    if (g_FileWatcher.hDir != INVALID_HANDLE_VALUE)
        CancelIoEx(g_FileWatcher.hDir, NULL);

    // The caller (WM_DESTROY) will call g_ThreadMgr.shutdownAll() which joins
    // the thread.  We only close the kernel handles here.
    if (g_FileWatcher.hDir != INVALID_HANDLE_VALUE) {
        // Give the thread a brief moment to observe OPERATION_ABORTED and
        // self-close; otherwise CloseHandle races with GetOverlappedResult.
        // 500 ms is generous — the OVERLAPPED cancel is near-instant.
        for (int i = 0; i < 50 && g_FileWatcher.running.load(); ++i)
            Sleep(10);
        CloseHandle(g_FileWatcher.hDir);
        g_FileWatcher.hDir = INVALID_HANDLE_VALUE;
    }
    if (g_FileWatcher.hShutdown) {
        CloseHandle(g_FileWatcher.hShutdown);
        g_FileWatcher.hShutdown = NULL;
    }
    g_FileWatcher.rootDir.clear();
    g_FileWatcher.running.store(false);
}

// Begin watching `rootDir` and post WM_FILE_REMOVED to `hwndOwner`.
// Restarts cleanly if a watcher is already running.
// v4.11: spawns via g_ThreadMgr (std::thread, joined at shutdown).
static bool FileWatcherStart(HWND hwndOwner, const std::wstring& rootDir) {
    FileWatcherStop();

    std::wstring watchRoot = FW_StripTrailingSep(rootDir.empty() ? g_TreeRootDir : rootDir);
    if (watchRoot.empty()) return false;

    g_FileWatcher.rootDir = watchRoot;
    g_FileWatcher.hDir    = INVALID_HANDLE_VALUE;
    g_FileWatcher.hShutdown = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_FileWatcher.hShutdown) {
        g_FileWatcher.rootDir.clear();
        return false;
    }

    g_FileWatcher.running.store(true);

    // v4.11: use std::thread tracked by g_ThreadMgr instead of _beginthreadex.
    g_ThreadMgr.spawn([hwndOwner]() {
        FileWatcherThreadBody(hwndOwner);
    });
    return true;
}

// UI-thread handler invoked from WindowProc on WM_FILE_REMOVED.
// v4.11: drains g_FileRemovedQueue (no raw lParam pointer).
static void HandleFileRemovedMessage() {
    while (true) {
        std::wstring path = g_FileRemovedQueue.try_pop();
        if (path.empty()) break;
        if (!g_hDirTree || !IsWindow(g_hDirTree)) continue;
        HTREEITEM hItem = SidebarFindPathItem(path);
        if (!hItem) continue;
        TreeView_DeleteItem(g_hDirTree, hItem);
        g_TreeMap.erase(hItem);
    }
}

// UI-thread handler invoked from WindowProc on WM_SIDEBAR_REFRESH.
// v4.15: triggered by the watcher thread when a new file or directory appears
// under the watched root (FILE_ACTION_ADDED / RENAMED_NEW_NAME), or when the
// kernel notification buffer overflows (bytes == 0 sentinel).
//
// Design notes:
//   • g_SidebarRefreshPending is cleared BEFORE kicking the async rescan so
//     the watcher thread can re-arm immediately: if another structural change
//     arrives while DirLoadThreadBody is still enumerating the disk, the watcher
//     will post a fresh WM_SIDEBAR_REFRESH the moment compare_exchange succeeds.
//     This closes the "silent gap" where an addition during a rescan is missed.
//   • SidebarLoadDirectory is fully asynchronous (g_ThreadMgr.spawn →
//     DirLoadThreadBody → WM_DIRECTORY_LOADED → HandleDirectoryLoaded).
//     The UI thread is never blocked.
//   • The current sidebar selection is preserved across the rescan by passing
//     it as selectAfterLoad; HandleDirectoryLoaded calls SidebarSelectPath once
//     the rebuilt tree is displayed.
static void HandleSidebarRefreshMessage(HWND hwnd) {
    // Clear the coalescing gate FIRST so the watcher can re-arm without delay.
    g_SidebarRefreshPending.store(false);

    if (g_TreeRootDir.empty() || !g_hDirTree || !IsWindow(g_hDirTree)) return;

    // Preserve selection: prefer the currently highlighted sidebar path;
    // fall back to the active editor file so the tree stays in sync even
    // when no tree item is explicitly selected.
    std::wstring restorePath = SidebarGetSelectedPath();
    if (restorePath.empty()) {
        EditorTab* active = GetActiveTab();
        if (active) restorePath = active->sFilePath;
    }

    SidebarLoadDirectory(hwnd, g_TreeRootDir, /*forceRefresh=*/true, restorePath);
}

// v4.32 — coalescing timer id for EN_CHANGE work. Picked outside the
// MESSAGE_TIMER_ID (999) range used by EditSubclassProc so the two
// timers never collide even if a future change moves them onto the
// same HWND. 16 ms = one frame at 60 Hz.
const UINT_PTR IDT_EN_CHANGE_COALESCE = 0xE1C0;

// v4.34 — additional coalescing timers and tunables for the smooth-typing pass.
//   IDT_STATS_DEFER_COALESCE  : long-pause word/char stats for huge docs (250 ms)
//   IDT_GUTTER_LAYOUT_DEFER   : digit-width relayout debounce (100 ms)
const UINT_PTR IDT_STATS_DEFER_COALESCE  = 0xE1C2;
const UINT_PTR IDT_GUTTER_LAYOUT_DEFER   = 0xE1C3;

// Documents larger than this (in wchar_t) take the deferred stats path.
// 2 MiB chars = ~4 MiB of UTF-16 in RAM; small enough that the fast
// path still feels instantaneous, large enough that 99% of source files
// keep their original behaviour.
const size_t TF_STATS_FAST_PATH_BYTES = 2u * 1024u * 1024u;

// Per-line WM_PAINT tokenisation cap. The horizontal clipper drops
// pixels past the right edge anyway; we just stop scanning so a
// minified one-line file can't melt the renderer.
const int TF_PAINT_MAX_LINE_CHARS = 8192;

// v4.34 — single entry point that every typing/edit hot path calls
// instead of doing synchronous Update*/Invalidate work. Re-arming the
// 16 ms one-shot timer naturally collapses bursts of keystrokes into
// one heavy-work pass after the user pauses.
inline void RequestEditUiRefresh(HWND hMainWnd) noexcept {
    // v4.35 S4 — reentrancy guard. A SetTimer call cannot recurse, but a
    // hostile message hook could re-enter this helper between the
    // WindowAlive check and SetTimer. The thread_local flag pins us to
    // a single in-flight call per UI thread.
    static thread_local bool inFlight = false;
    if (inFlight) return;
    if (!TF_Safety::WindowAlive(hMainWnd)) return;
    // v4.35 S4 — thread affinity. SetTimer across threads silently
    // creates a timer the wrong message pump will never receive,
    // leaking the slot. Reject cross-thread calls outright.
    DWORD wndTid = ::GetWindowThreadProcessId(hMainWnd, nullptr);
    if (wndTid != ::GetCurrentThreadId()) return;
    inFlight = true;
    ::SetTimer(hMainWnd, IDT_EN_CHANGE_COALESCE, 16, NULL);
    inFlight = false;
}

LRESULT CALLBACK WindowProcImpl(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    // v4.41 — autosave heartbeat.  We intercept BEFORE the main switch
    // so an existing WM_TIMER handler with our id is impossible (the id
    // 0xFA00 is private to tf_v441::Reliability).  The handler dispatches
    // the snapshot to a worker thread — UI is never blocked.
    if (uMsg == WM_TIMER && wParam == tf_v441::Reliability::IDT_AUTOSAVE) {
        tf_v441::Reliability::RunAutosavePass();
        return 0;
    }
    static HWND hCmdInput, hExecBtn, hCheckBtn, hLbl;
    static HWND hSearchLbl, hSearchInput, hSearchBtn, hSearchUpBtn, hSyntaxBtn;
    static HWND hGlobalWordCount, hGlobalCharCount;

    switch (uMsg) {

    case WM_FILE_LOAD_FAILED: {
        // lParam is a doorbell — drain the failed-load queue.
        while (true) {
            auto up = g_FileLoadFailedQueue.try_pop();
            if (!up) break;
            FileLoadPayload* payload = up.get();

            // v4.40: user closed the loading tab.  The progress entry was
            // already detached by RemoveTab; silently delete the quarantined
            // tab object and do not show an error for a file the user discarded.
            if (TF_IsLoadAbandoned(payload->loadId)) {
                TF_FinalDeleteAbandonedTabByLoadId(hwnd, payload->loadId);
                UpdateTitle(hwnd);
                continue;
            }

            // v21: clean up the reserved hourglass tab (if any) so the user
            // isn't left staring at a "⏳ filename" tab after a failed load.
            if (payload->bFromSidebar) {
                // v4.44 O2: STRICT id + loadId verification.  No path fallback.
                TabHandle h{payload->targetTabId};
                EditorTab* candidate = h.resolve();
                if (candidate && candidate->bAsyncLoading &&
                    candidate->loadId == payload->loadId) {
                    for (size_t i = 0; i < g_Tabs.size(); ++i) {
                        if (g_Tabs[i].get() != candidate) continue;
                        candidate->bAsyncLoading      = false;
                        candidate->bPurgedNeedsReload = false;
                        candidate->loadId             = 0;
                        candidate->cancelToken.reset();
                        candidate->bCloseAfterAsyncLoadCancel = false;
                        // Restore caption to the plain filename (drop hourglass).
                        TCITEMW tie = { 0 };
                        tie.mask    = TCIF_TEXT;
                        tie.pszText = const_cast<LPWSTR>(candidate->sFileName.c_str());
                        TabCtrl_SetItem(hGlobalTabCtrl, (int)i, &tie);
                        break;
                    }
                } else {
                    TF_DROP_LOG(L"WM_FILE_LOAD_FAILED: no live tab matches targetTabId+loadId");
                }
            }
            std::wstring msg = L"Failed to open:\n" + payload->sFilePath;
            if (payload->dwError) {
                wchar_t buf[64];
                swprintf(buf, 64, L"\n\nError code: %lu", (unsigned long)payload->dwError);
                msg += buf;
            }
            // v4.22: route through TF_MsgError — promotes to the root
            // window and uses MB_TASKMODAL so a still-arriving load
            // doorbell can't quietly close the dialog.
            TF_MsgError(hwnd, msg.c_str(), L"File Load Error");
            // v4.28: ATOMIC remove + count under the registry mutex so a
            // racing completer can't also observe "I'm last" and double-hide.
            size_t remainingInReg = TF_LoadRegistry_RemoveAndCount(payload->loadId);
            int    remainingCtr   = g_ActiveLoads.fetch_sub(1) - 1;
            if (remainingCtr < 0) { g_ActiveLoads.store(0); remainingCtr = 0; }
            if (remainingInReg == 0 && remainingCtr <= 0) {
                HideLoadProgressUI(hwnd);
            } else {
                TF_RenderLoadLabel(hwnd);
            }
        }
        UpdateTitle(hwnd);
        return 0;
    }

    case WM_FILE_LOAD_PROGRESS: {
        // v4.28: WPARAM = READ percent (0..100). LPARAM = stable per-load id
        // (the same pointer BeginAsyncFileLoadEx captured via payload.get()).
        // Routes to LoadPhase::Reading slot — never overwrites renderPct.
        LoadId loadId = (LoadId)lParam;
        if (TF_IsLoadAbandoned(loadId)) return 0;
        if (loadId && TF_LoadRegistry_SetPercent(loadId, (int)wParam,
                                                 LoadPhase::Reading)) {
            TF_RenderLoadLabel(hwnd);
        } else {
            // No registry entry (legacy / shutdown): fall back to direct bar set.
            SetLoadProgressPercent((int)wParam);
        }
        return 0;
    }

    case WM_FILE_RENDER_PROGRESS: {
        // v4.28: WPARAM = RENDER percent (0..100). LPARAM = same loadId.
        // Posted by BulkSetEditText between EM_REPLACESEL chunks while the
        // file's text is being streamed into the EDIT control.  Updates the
        // renderPct slot so the overlay shows "Rendering: foo.cpp 47%" while
        // a concurrent load can still freely update its own readPct.
        LoadId loadId = (LoadId)lParam;
        if (TF_IsLoadAbandoned(loadId)) return 0;
        if (loadId && TF_LoadRegistry_SetPercent(loadId, (int)wParam,
                                                 LoadPhase::Rendering)) {
            TF_RenderLoadLabel(hwnd);
        }
        return 0;
    }

    case WM_FILE_LOAD_COMPLETE: {
        // lParam is a doorbell — drain the successful-load queue.
        while (true) {
            auto up = g_FileLoadQueue.try_pop();
            if (!up) break;
            FileLoadPayload* payload = up.get();

            // v4.40: the user closed this loading tab after the worker started.
            // RemoveTab already took it out of the visible tab strip and detached
            // its overlay entry, so completion must be a pure discard.  Never
            // fall through to non-sidebar reuse/CreateNewTab; that was the root
            // of the blank-tab/orphan-progress crash pattern.
            if (TF_IsLoadAbandoned(payload->loadId)) {
                TF_FinalDeleteAbandonedTabByLoadId(hwnd, payload->loadId);
                UpdateTitle(hwnd);
                continue;
            }

        const std::wstring& wstr = payload->text;

        // ---- Tab reuse logic ----
        // v21: Sidebar-issued loads ALREADY reserved a tab (with bAsyncLoading=true
        // and sFilePath stamped) before BeginAsyncFileLoadEx. Find that tab by path
        // and refill it in place — do NOT call CreateNewTab, which would produce a
        // second tab with the same filename and leave the hourglass tab orphaned.
        EditorTab* tab = nullptr;
        int        tabIndex = -1;
        if (payload->bFromSidebar) {
            // v4.44 O2: STRICT id-based lookup.  We resolve via the stable
            // tab id the worker carries (TabHandle::resolve validates the
            // tab is still alive AND in lifecycle == Alive) and then we
            // verify loadId matches.  No path-name fallback — that was the
            // residual implicit-ownership channel.
            TabHandle h{payload->targetTabId};
            EditorTab* candidate = h.resolve();
            if (candidate && candidate->bAsyncLoading &&
                candidate->loadId == payload->loadId) {
                // Find its current index in g_Tabs (positions can shift if
                // siblings were closed between worker spawn and completion).
                for (size_t i = 0; i < g_Tabs.size(); ++i) {
                    if (g_Tabs[i].get() == candidate) {
                        tab = candidate;
                        tabIndex = (int)i;
                        break;
                    }
                }
            }
            if (tab && tabIndex != g_ActiveTabIndex) {
                TabCtrl_SetCurSel(hGlobalTabCtrl, tabIndex);
                g_ActiveTabIndex = tabIndex;
            }
            // v4.39: the hourglass tab was closed (RemoveTab) or the whole
            // app is being torn down.  Discard the payload silently — do
            // NOT fall through to the non-sidebar branch, which would dump
            // a hundred-MB load into an unrelated tab and produce the
            // "blank tab populated by someone else's file" bug.
            if (!tab) {
                size_t reg_remaining = TF_LoadRegistry_RemoveAndCount(payload->loadId);
                int    ctr_remaining = g_ActiveLoads.fetch_sub(1) - 1;
                if (ctr_remaining < 0) { g_ActiveLoads.store(0); ctr_remaining = 0; }
                if (reg_remaining == 0 && ctr_remaining <= 0) HideLoadProgressUI(hwnd);
                else                                          TF_RenderLoadLabel(hwnd);
                UpdateTitle(hwnd);
                continue;   // unique_ptr `up` drops here -> RAM reclaimed
            }
        }
        if (!tab) {
            // Non-sidebar path (DoFileOpen / WM_DROPFILES) — original behaviour.
            EditorTab* active = GetActiveTab();
            bool reuseTab = active && !active->bModified && active->sFilePath.empty()
                            && GetWindowTextLength(active->hEdit) == 0;
            if (!reuseTab) CreateNewTab(hwnd);
            tab      = GetActiveTab();
            tabIndex = g_ActiveTabIndex;
        }
        if (!tab) { UpdateTitle(hwnd); continue; }

        // ---- Data-integrity audit (v4.28) ----
        // The worker FNV-1a-hashes the raw bytes; we trust the worker's
        // truncation flag.  A truncated payload is logged but still
        // committed so the user gets to see what loaded — they decide
        // whether to discard via the toast.  No silent corruption.
        if (payload->bTruncated) {
            wchar_t warn[256];
            _snwprintf_s(warn, _countof(warn), _TRUNCATE,
                         L"%ls truncated: %lld of %lld bytes read.",
                         payload->sFileName.c_str(),
                         payload->llBytesRead, payload->llFileSize);
            // Use the toast-style status if available; OutputDebugStringW
            // is the universal fallback that never fails.
            OutputDebugStringW(warn);
        }

        // ---- Push text into the EDIT control ----
        // v20: For large documents we stream the text in chunks while
        // pumping the message loop, so the UI stays responsive instead
        // of freezing inside a single SetWindowTextW for tens of
        // seconds. The EN_CHANGE handler early-returns while
        // g_bBulkLoading is true, so no per-chunk recolor / line-count
        // / word-count work fires during the insert.
        // v4.28: WM_SETREDRAW gating now via EditRedrawSuspendGuard so an
        // exception in the piece-table ingest below cannot leave the EDIT
        // control stuck in redraw=FALSE state.
        const bool bulk = wstr.size() >= BULK_LOAD_THRESHOLD_CHARS;
        {
            EditRedrawSuspendGuard redrawGuard(tab->hEdit);
            RestoreGuard guard(&tab->isRestoring);
            g_bBulkLoading.store(true, std::memory_order_release);
            if (bulk) {
                // v4.28: flip phase + capture the wide-char "rendering size"
                // BEFORE the chunk loop so the very first label re-render
                // says "Rendering: foo.cpp (X MB) 0%" instead of leaving
                // "Reading 100%" briefly stuck on screen.
                {
                    long long renderBytes =
                        (long long)(wstr.size() * sizeof(wchar_t));
                    TF_LoadRegistry_SetPhase(payload->loadId,
                                             LoadPhase::Rendering,
                                             &payload->sFileName,
                                             &renderBytes);
                    TF_RenderLoadLabel(hwnd);
                }
                BulkSetEditText(tab->hEdit, wstr, hwnd, payload->loadId, payload->cancelToken);
            } else {
                if (tab->hEdit && IsWindow(tab->hEdit))
                    SetWindowTextW(tab->hEdit, wstr.c_str());
            }
            g_bBulkLoading.store(false, std::memory_order_release);
            // redrawGuard's dtor re-enables WM_SETREDRAW + invalidates.
        }

        // v4.40: RemoveTab can run re-entrantly from BulkSetEditText's message
        // pump.  If it quarantined this load while the chunk loop was active,
        // stop here before touching metadata, piece tables, gutters, or focus.
        if (TF_IsLoadAbandoned(payload->loadId)) {
            TF_FinalDeleteAbandonedTabByLoadId(hwnd, payload->loadId);
            UpdateTitle(hwnd);
            continue;
        }

        // ---- Tab metadata ----
        tab->sFilePath      = payload->sFilePath;
        tab->sFileName      = payload->sFileName;
        tab->bModified      = false;
        tab->errorLine      = -1;
        tab->cachedDocDirty = true;

        // ---- Piece Table ingest ----
        tab->pt.LoadOriginal(wstr);
        tab->ptDirty = false;

        // ---- Disk-state hash from the piece table's virtual text ----
        tab->initialContentHash = std::hash<std::wstring>{}(tab->pt.GetVirtualText());

        // ---- Seed undo stack with initial content ----
        tab->undoStack.clear();
        tab->redoStack.clear();
        {
            std::wstring initText = tab->pt.GetVirtualText();
            tab->undoStack.emplace_back(std::move(initText), 0, 0, 0);
        }

        // ---- Tab caption ----
        TCITEM tie;
        tie.mask    = TCIF_TEXT;
        tie.pszText = (LPWSTR)tab->sFileName.c_str();
        TabCtrl_SetItem(hGlobalTabCtrl, tabIndex >= 0 ? tabIndex : g_ActiveTabIndex, &tie);

        // v4.28: ATOMIC remove + count.  We do the registry erase HERE (before
        // the gutter / scrollbar redraws below) so that if this was the last
        // outstanding load, the overlay can be hidden and the underlying area
        // re-painted before the gutter math runs.  The matching `int remaining`
        // is consumed below where g_ActiveLoads is decremented; we capture
        // the registry-side count separately so we don't race a second
        // completer that drains the same WM_FILE_LOAD_COMPLETE batch.
        const size_t reg_remaining_after_this = TF_LoadRegistry_RemoveAndCount(payload->loadId);
        const bool   isLastInBatch            = (reg_remaining_after_this == 0);
        if (isLastInBatch) {
            HideLoadProgressUI(hwnd);
        } else {
            // Other loads still in flight — refresh the label so percentages
            // for the survivors are accurate immediately.
            TF_RenderLoadLabel(hwnd);
        }

        // ---- All GDI / status readouts ----
        UpdateLineCount(tab->hEdit, hGlobalLineCount);
        UpdateWordCount(tab->hEdit, hWordCount);
        UpdateCharacterCount(tab->hEdit, hCharLabel);

        // v4.23: Force a full child re-layout — this is exactly what
        // tab-switching / sidebar-toggling does, and it is the only
        // sequence that reliably re-seats the gutter's cached
        // firstVisibleLine after a bulk EM_SETTEXT. Without this, the
        // gutter paints once *before* the edit control finishes its
        // internal line-break recompute, so it shows blank or stale
        // numbers until the next WM_SIZE arrives organically.
        {
            RECT rcClient{};
            if (GetClientRect(hwnd, &rcClient)) {
                SendMessageW(hwnd, WM_SIZE, SIZE_RESTORED,
                             MAKELPARAM(rcClient.right - rcClient.left,
                                        rcClient.bottom - rcClient.top));
            }
        }

        UpdateGutter(tab->hEdit, tab->hGutter);
        // v4.22/4.23: belt-and-braces explicit gutter invalidation +
        // synchronous repaint so numbers appear without waiting for
        // the next paint cycle.
        if (tab->hGutter && IsWindow(tab->hGutter)) {
            InvalidateRect(tab->hGutter, NULL, TRUE);
            UpdateWindow(tab->hGutter);
        }
        if (tab->hEdit && IsWindow(tab->hEdit)) {
            // Nudge the edit control so it republishes its scroll state;
            // some Win32 builds don't fire EN_VSCROLL after EM_SETSEL(0,0)
            // following a bulk load, leaving the gutter stale.
            SendMessageW(tab->hEdit, EM_SCROLLCARET, 0, 0);
        }
        UpdateColInfo(tab->hEdit);
        UpdatePieceCount(tab);
        CaptureBaseline(tab->hEdit);

        // ---- Workspace anchor (preserves File>Open / Recent-Folder pinning rules) ----
        std::wstring workspaceRoot = std::filesystem::path(tab->sFilePath).parent_path().wstring();
        if (!payload->sWorkspaceHint.empty()
            && SidebarPathIsUnderRoot(tab->sFilePath, payload->sWorkspaceHint)) {
            workspaceRoot = payload->sWorkspaceHint;
        }
        SidebarLoadDirectory(hwnd, workspaceRoot, true, tab->sFilePath);

        // ---- v19: also commit the explicit workspace root when the sidebar issued the load.
        if (payload->bFromSidebar && !payload->sWorkspaceRoot.empty()) {
            tab->sWorkspaceRoot = payload->sWorkspaceRoot;
        }
        tab->bPurgedNeedsReload = false; // reload satisfied if this was a purged tab refill
        tab->bAsyncLoading      = false; // v21: clear in-flight marker
        tab->loadId            = 0; tab->cancelToken.reset(); // v4.40: load token consumed
        tab->bCloseAfterAsyncLoadCancel = false;

        // ---- Final title + focus ----
        UpdateTitle(hwnd);
        SetFocus(tab->hEdit);

        // v4.28: registry entry was already removed atomically above (see
        // `reg_remaining_after_this`).  Here we only sync the `g_ActiveLoads`
        // counter and decide whether to hide the overlay if it wasn't already
        // hidden (cheap idempotent guard — HideLoadProgressUI returns early
        // when the panel isn't visible).
        int remaining = g_ActiveLoads.fetch_sub(1) - 1;
        if (remaining < 0) { g_ActiveLoads.store(0); remaining = 0; }
        if (remaining == 0 && isLastInBatch) {
            // Already hidden by the early-out above; nothing more to do.
        } else if (remaining == 0) {
            HideLoadProgressUI(hwnd);
        } else if (!isLastInBatch) {
            TF_RenderLoadLabel(hwnd);
        }
        // unique_ptr `up` goes out of scope here — payload freed automatically
        } // end while drain loop
        return 0;
    }
    case WM_CREATE: {
        HICON hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_APP_ICON));
        SendMessage(hwnd, WM_SETICON, ICON_BIG,   (LPARAM)hIcon);
        SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);

        INITCOMMONCONTROLSEX icex = { sizeof(icex), ICC_TAB_CLASSES | ICC_TREEVIEW_CLASSES | ICC_PROGRESS_CLASS };
        InitCommonControlsEx(&icex);

        // Load persisted sidebar width from the registry (before creating children).
        LoadSidebarWidth();

        // ---------------------------------------------------------------
        //  Register the custom splitter bar window class (one-time, idempotent).
        // ---------------------------------------------------------------
        {
            WNDCLASSEXW wcs = {};
            wcs.cbSize        = sizeof(wcs);
            wcs.style         = CS_HREDRAW | CS_VREDRAW;
            wcs.lpfnWndProc   = SplitterWndProc;
            wcs.hInstance     = GetModuleHandle(NULL);
            wcs.hCursor       = LoadCursor(NULL, IDC_SIZEWE);
            wcs.hbrBackground = (HBRUSH)GetStockObject(DKGRAY_BRUSH);
            wcs.lpszClassName = k_SplitterClass;
            RegisterClassExW(&wcs); // if already registered, silently fails — that's fine
        }

        // ---------------------------------------------------------------
        //  SIDEBAR — WC_TREEVIEW directory navigator
        //  Created before any tab controls so it sits behind them in Z-order.
        // ---------------------------------------------------------------
        g_hDirTree = CreateWindowEx(
            WS_EX_CLIENTEDGE,
            WC_TREEVIEW,
            L"",
            WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS |
            TVS_HASLINES | TVS_HASBUTTONS | TVS_LINESATROOT |
            TVS_SHOWSELALWAYS | WS_VSCROLL,
            0, 28,             // x=0, y below tab-bar row
            g_sidebarWidth,    // dynamic width (from registry or default)
            400,               // placeholder; WM_SIZE will correct this
            hwnd,
            (HMENU)IDC_DIR_TREE,
            GetModuleHandle(NULL),
            NULL);
        // Dark-mode colours for the tree.
        if (g_hDirTree) {
            TreeView_SetBkColor(g_hDirTree,   RGB(30, 30, 30));
            TreeView_SetTextColor(g_hDirTree, RGB(200, 200, 200));
        }
        if (!g_sidebarVisible && g_hDirTree) ShowWindow(g_hDirTree, SW_HIDE);

        g_hNewFolderBtn = CreateWindowEx(
            0, L"BUTTON", L"+ Folder",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_CLIPSIBLINGS,
            0, 0, 90, 25,
            hwnd, (HMENU)IDC_NEW_FOLDER_BTN,
            GetModuleHandle(NULL), NULL);
        if (!g_sidebarVisible && g_hNewFolderBtn) ShowWindow(g_hNewFolderBtn, SW_HIDE);

        // ---------------------------------------------------------------
        //  SPLITTER BAR — sits immediately to the right of the tree.
        // ---------------------------------------------------------------
        g_hSplitter = CreateWindowExW(
            0,
            k_SplitterClass,
            L"",
            WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
            g_sidebarWidth, 28,   // placeholder; WM_SIZE corrects it
            SPLITTER_WIDTH, 400,
            hwnd,
            NULL,
            GetModuleHandle(NULL),
            NULL);
        if (!g_sidebarVisible && g_hSplitter) ShowWindow(g_hSplitter, SW_HIDE);

        hGlobalTabCtrl = CreateWindowEx(0, WC_TABCONTROL, L"",
            WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS |
            TCS_OWNERDRAWFIXED | TCS_FIXEDWIDTH,
            0, 0, 0, 0, hwnd, (HMENU)IDC_MAIN_TAB, GetModuleHandle(NULL), NULL);
        TabCtrl_SetItemSize(hGlobalTabCtrl, 120, 25);

        OldTabProc = (WNDPROC)SetWindowLongPtr(hGlobalTabCtrl, GWLP_WNDPROC,
                                                (LONG_PTR)TabSubclassProc);

        hLbl      = CreateWindowEx(0, L"STATIC", L" Command:",
                                    WS_CHILD | WS_VISIBLE,
                                    0, 0, 0, 0, hwnd, NULL, GetModuleHandle(NULL), NULL);
        hCmdInput = CreateWindowEx(WS_EX_CLIENTEDGE, L"EDIT", L"python",
                                    WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                    0, 0, 0, 0, hwnd, (HMENU)IDC_COMMAND_EDIT,
                                    GetModuleHandle(NULL), NULL);
        hExecBtn  = CreateWindowEx(0, L"BUTTON", L"EXECUTE",
                                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                    0, 0, 0, 0, hwnd, (HMENU)IDC_EXECUTE_BTN,
                                    GetModuleHandle(NULL), NULL);
        hCheckBtn = CreateWindowEx(0, L"BUTTON", L"CHECK",
                                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                    0, 0, 0, 0, hwnd, (HMENU)IDC_CHECK_BTN,
                                    GetModuleHandle(NULL), NULL);

        hGlobalLineCount = CreateWindowEx(0, L"STATIC", L"Lines: 1",
                                           WS_CHILD | WS_VISIBLE | SS_RIGHT,
                                           0, 0, 0, 0, hwnd, (HMENU)IDC_LINE_COUNT,
                                           GetModuleHandle(NULL), NULL);
        hGlobalWordCount = CreateWindowEx(0, L"STATIC", L"Words: 0",
                                           WS_CHILD | WS_VISIBLE | SS_RIGHT,
                                           0, 0, 0, 0, hwnd, NULL,
                                           GetModuleHandle(NULL), NULL);
        hGlobalCharCount = CreateWindowEx(0, L"STATIC", L"Chars: 0",
                                           WS_CHILD | WS_VISIBLE | SS_RIGHT,
                                           0, 0, 0, 0, hwnd, NULL,
                                           GetModuleHandle(NULL), NULL);
        hGlobalColInfo   = CreateWindowEx(0, L"STATIC", L"Col: 1",
                                           WS_CHILD | WS_VISIBLE | SS_RIGHT,
                                           0, 0, 0, 0, hwnd, (HMENU)IDC_COLUMN_INFO,
                                           GetModuleHandle(NULL), NULL);
        hGlobalPieceCount = CreateWindowEx(0, L"STATIC", L"Pieces: 0",
                                           WS_CHILD | WS_VISIBLE | SS_RIGHT,
                                           0, 0, 0, 0, hwnd, NULL,
                                           GetModuleHandle(NULL), NULL);

        hWordCount = hGlobalWordCount;
        hCharLabel = hGlobalCharCount;

        // Wire up module-level aliases used by ApplySidebarWidth / splitter.
        hGlobalLbl       = hLbl;
        hGlobalCmdInput  = hCmdInput;
        hGlobalCheckBtn  = hCheckBtn;
        hGlobalExecBtn   = hExecBtn;

        hSearchLbl   = CreateWindowEx(0, L"STATIC", L" Search:",
                                       WS_CHILD | WS_VISIBLE,
                                       0, 0, 0, 0, hwnd, NULL, GetModuleHandle(NULL), NULL);
        hSearchInput = CreateWindowEx(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                       WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                       0, 0, 0, 0, hwnd, (HMENU)IDC_SEARCH_EDIT,
                                       GetModuleHandle(NULL), NULL);
        hSearchBtn   = CreateWindowEx(0, L"BUTTON", L"DN",
                                       WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                       0, 0, 0, 0, hwnd, (HMENU)IDC_SEARCH_BTN,
                                       GetModuleHandle(NULL), NULL);
        hSearchUpBtn = CreateWindowEx(0, L"BUTTON", L"UP",
                                       WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                       0, 0, 0, 0, hwnd, (HMENU)IDC_SEARCH_UP_BTN,
                                       GetModuleHandle(NULL), NULL);
        hSyntaxBtn   = CreateWindowEx(0, L"BUTTON", L"SYN: ON",
                                       WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                       0, 0, 0, 0, hwnd, (HMENU)IDC_SYNTAX_TOGGLE,
                                       GetModuleHandle(NULL), NULL);

        // Sidebar visibility toggle button — positions corrected by WM_SIZE.
        g_hSidebarToggleBtn = CreateWindowEx(
            0, L"BUTTON",
            g_sidebarVisible ? L"\u25c0 Tree" : L"Tree \u25b6",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_CLIPSIBLINGS,
            0, 0, 80, 25,
            hwnd, (HMENU)IDC_SIDEBAR_TOGGLE,
            GetModuleHandle(NULL), NULL);

        // Wire up remaining module-level aliases.
        hGlobalSyntaxBtn = hSyntaxBtn;
        hGlobalSearchLbl = hSearchLbl;
        hGlobalSearchIn  = hSearchInput;
        hGlobalSearchBtn = hSearchBtn;
        hGlobalSearchUp  = hSearchUpBtn;

        hUIFont = CreateFont(18, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                              DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
        hEditorFont = CreateFont(nCurrentFontSize, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");

        HWND hFontTargets[] = {
            hGlobalTabCtrl, hLbl, hCmdInput, hExecBtn, hCheckBtn,
            hGlobalLineCount, hGlobalWordCount, hGlobalCharCount, hGlobalColInfo,
            hGlobalPieceCount,
            hSearchLbl, hSearchInput, hSearchBtn, hSearchUpBtn, hSyntaxBtn,
            g_hSidebarToggleBtn, g_hNewFolderBtn
        };
        for (HWND target : hFontTargets)
            SendMessage(target, WM_SETFONT, (WPARAM)hUIFont, TRUE);

        {
            HWND hTmp = CreateWindow(L"EDIT", L"", 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL);
            OldEditProc = (WNDPROC)GetWindowLongPtr(hTmp, GWLP_WNDPROC);
            DestroyWindow(hTmp);
        }

        hBackBrush   = CreateSolidBrush(BG_COLOR);
        hGutterBrush = CreateSolidBrush(GUTTER_BG);
        hDotBrush    = CreateSolidBrush(DOT_COLOR);
        hMatchBrush  = CreateSolidBrush(BRACKET_MATCH);
        if (!hBackBrush || !hGutterBrush || !hDotBrush || !hMatchBrush) {
            if (hBackBrush)   { DeleteObject(hBackBrush);   hBackBrush   = NULL; }
            if (hGutterBrush) { DeleteObject(hGutterBrush); hGutterBrush = NULL; }
            if (hDotBrush)    { DeleteObject(hDotBrush);    hDotBrush    = NULL; }
            if (hMatchBrush)  { DeleteObject(hMatchBrush);  hMatchBrush  = NULL; }
            MessageBoxW(hwnd, L"Could not create required drawing resources.",
                        L"Startup Error", MB_OK | MB_ICONERROR);
            return -1;
        }

        HMENU hMenu     = CreateMenu();
        HMENU hFileMenu = CreateMenu();
        AppendMenu(hFileMenu, MF_STRING, IDM_FILE_NEW,    L"&New\tCtrl+N");
        AppendMenu(hFileMenu, MF_STRING, IDM_FILE_OPEN,   L"&Open\tCtrl+O");
        AppendMenu(hFileMenu, MF_STRING, IDM_FILE_SAVE,   L"&Save\tCtrl+S");
        AppendMenu(hFileMenu, MF_STRING, IDM_FILE_SAVEAS, L"Save &As...\tCtrl+Shift+S");

        HMENU hRecentMenu = CreatePopupMenu();
        AppendMenu(hFileMenu, MF_POPUP, (UINT_PTR)hRecentMenu, L"Recent Folders");
        AppendMenu(hFileMenu, MF_SEPARATOR, 0, NULL);
        AppendMenu(hFileMenu, MF_STRING, IDM_FILE_EXIT, L"&Exit");
        AppendMenu(hMenu, MF_POPUP, (UINT_PTR)hFileMenu, L"&File");

        HMENU hEditMenu = CreateMenu();
        AppendMenu(hEditMenu, MF_STRING, IDM_AUTOFILL_MANAGE,
                   L"&Manage Autofill Words...");
        AppendMenu(hEditMenu, MF_SEPARATOR, 0, NULL);
        AppendMenu(hEditMenu, MF_STRING, IDM_PURGE_TAB_RAM,
                   L"&Purge Current Tab RAM\tCtrl+Shift+R");
        AppendMenu(hMenu, MF_POPUP, (UINT_PTR)hEditMenu, L"&Edit");

        SetMenu(hwnd, hMenu);
        UpdateRecentFoldersMenu(hwnd);
        CreateNewTab(hwnd);

        DragAcceptFiles(hwnd, TRUE);
        break;
    }

case WM_DROPFILES: {
    HDROP hDrop = (HDROP)wParam;
    struct DragGuard { HDROP h; ~DragGuard() { DragFinish(h); } } dGuard{ hDrop };

    UINT fileCount = DragQueryFileW(hDrop, 0xFFFFFFFF, NULL, 0);
    for (UINT i = 0; i < fileCount; i++) {
        UINT length = DragQueryFileW(hDrop, i, NULL, 0);
        if (length == 0) continue;

        std::wstring droppedPath(length, L'\0');
        DragQueryFileW(hDrop, i, droppedPath.data(), length + 1);

        // Workspace hint snapshot (UI thread).
        std::wstring workspaceHint = g_NextOpenDir;

        // Fire the background loader. Result is delivered via WM_FILE_LOAD_COMPLETE.
        BeginAsyncFileLoad(hwnd, droppedPath, workspaceHint);
    }
    return 0;
}


    case WM_SYNTAX_CHECK_COMPLETE:
        HandleSyntaxCheckComplete(hwnd, lParam);
        return 0;

    case WM_DIRECTORY_LOADED:
        HandleDirectoryLoaded(hwnd, lParam);
        return 0;

    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT lpdis = (LPDRAWITEMSTRUCT)lParam;
        if (lpdis->CtlID == IDC_MAIN_TAB) {
            wchar_t szText[MAX_PATH];
            TCITEM tie;
            tie.mask       = TCIF_TEXT;
            tie.pszText    = szText;
            tie.cchTextMax = MAX_PATH;
            TabCtrl_GetItem(hGlobalTabCtrl, lpdis->itemID, &tie);
            SetBkMode(lpdis->hDC, TRANSPARENT);
            if (lpdis->itemState & ODS_SELECTED) {
                FillRect(lpdis->hDC, &lpdis->rcItem, GetSysColorBrush(COLOR_BTNFACE));
                SetTextColor(lpdis->hDC, RGB(0, 0, 0));
            } else {
                FillRect(lpdis->hDC, &lpdis->rcItem, GetSysColorBrush(COLOR_BTNSHADOW));
                SetTextColor(lpdis->hDC, RGB(255, 255, 255));
            }
            RECT textRect  = lpdis->rcItem;
            textRect.left += 5;
            textRect.right -= 25;
            DrawText(lpdis->hDC, szText, -1, &textRect,
                     DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_END_ELLIPSIS);
            RECT closeRect = lpdis->rcItem;
            closeRect.left = closeRect.right - 25;
            DrawText(lpdis->hDC, L"x", -1, &closeRect,
                     DT_SINGLELINE | DT_VCENTER | DT_CENTER);
            return TRUE;
        }
        break;
    }

    case WM_NOTIFY: {
    // 1. Extreme Safety: Immediate validation of the notification header
    LPNMHDR pnmh = reinterpret_cast<LPNMHDR>(lParam);
    if (!pnmh || !IsWindow(pnmh->hwndFrom)) return 0;

    // ----------------------------------------------------------------
    // Sidebar Tree Intelligence (IDC_DIR_TREE)
    // ----------------------------------------------------------------
    if (pnmh->idFrom == IDC_DIR_TREE && g_hDirTree) {
        switch (pnmh->code) {
            case TVN_DELETEITEM: {
                LPNMTREEVIEW pnmtv = reinterpret_cast<LPNMTREEVIEW>(lParam);
                if (pnmtv->itemOld.hItem) {
                    // Safety: Ensure we don't use a stale handle
                    g_TreeMap.erase(pnmtv->itemOld.hItem);
                }
                return 0;
            }
            case TVN_GETDISPINFO: {
                LPNMTVDISPINFO pdi = reinterpret_cast<LPNMTVDISPINFO>(lParam);
                if (pdi->item.mask & TVIF_CHILDREN) {
                    pdi->item.cChildren = TreeView_GetChild(g_hDirTree, pdi->item.hItem) ? 1 : 0;
                }
                return 0;
            }
            case NM_DBLCLK: {
                HTREEITEM hSel = TreeView_GetSelection(g_hDirTree);
                if (hSel) {
                    const std::wstring& path = SidebarPathForItem(hSel);
                    if (!path.empty()) {
                        std::error_code ec;
                        if (fs::is_directory(path, ec)) {
                            TreeView_Expand(g_hDirTree, hSel, TVE_TOGGLE);
                        } else {
                            // Intelligence: This call now handles "pinning" the current root to the new tab
                            SidebarOpenFile(hwnd, path);
                        }
                    }
                }
                return 0;
            }
        }
    }

    // ----------------------------------------------------------------
    // Tab Control Intelligence (IDC_MAIN_TAB)
    // ----------------------------------------------------------------
    if (pnmh->idFrom == IDC_MAIN_TAB && hGlobalTabCtrl) {
        if (pnmh->code == TCN_SELCHANGE) {
            const int sel = TabCtrl_GetCurSel(hGlobalTabCtrl);
            if (sel == -1) return 0;

            // Perform the tab switch
            SwitchToTab(sel); 
            EditorTab* active = GetActiveTab();

            if (active) {
                // EXTREME INTELLIGENCE: Workspace Persistence
                // Instead of recalculating based on the file path (which might be in a subfolder),
                // we use the 'sWorkspaceRoot' that was pinned when the tab was created.
                if (!active->sWorkspaceRoot.empty()) {
                    // This keeps the parent folder intact even if the file is deep in a sub-sub-folder.
                    SidebarLoadDirectory(hwnd, active->sWorkspaceRoot, true, active->sFilePath);
                } else if (!active->sFilePath.empty()) {
                    // Fallback for files opened without a defined workspace
                    try {
                        std::wstring root = fs::path(active->sFilePath).parent_path().wstring();
                        if (!g_NextOpenDir.empty() && SidebarPathIsUnderRoot(active->sFilePath, g_NextOpenDir)) {
                            root = g_NextOpenDir;
                        }
                        active->sWorkspaceRoot = root; // Pin it now for future switches
                        SidebarLoadDirectory(hwnd, root, true, active->sFilePath);
                    } catch (...) {}
                }

                // EXTREME SAFETY: Atomic UI Refresh
                UpdateTitle(hwnd);

                RECT rc;
                if (GetClientRect(hwnd, &rc)) {
                    // Force re-layout to prevent gutter/editor misalignment
                    SendMessage(hwnd, WM_SIZE, 0, MAKELPARAM(rc.right, rc.bottom));
                }

                if (active->hEdit && IsWindow(active->hEdit)) {
                    UpdateGutter(active->hEdit, active->hGutter);

                    // Safety: Validate gutter window before invalidation
                    if (active->hGutter && IsWindow(active->hGutter)) {
                        InvalidateRect(active->hGutter, NULL, TRUE);
                    }

                    InvalidateRect(active->hEdit, NULL, TRUE);

                    // Batch update status/info bars
                    UpdateLineCount(active->hEdit, hGlobalLineCount);
                    UpdateWordCount(active->hEdit, hGlobalWordCount);
                    UpdateCharacterCount(active->hEdit, hGlobalCharCount);
                    UpdateColInfo(active->hEdit);
                    UpdatePieceCount(active);

                    SetFocus(active->hEdit);
                }
            }
            return 0;
        } 

        if (pnmh->code == NM_CLICK) {
            TCHITTESTINFO hti = { 0 };
            GetCursorPos(&hti.pt);
            ScreenToClient(hGlobalTabCtrl, &hti.pt);

            const int index = TabCtrl_HitTest(hGlobalTabCtrl, &hti);
            if (index != -1) {
                RECT rc;
                if (TabCtrl_GetItemRect(hGlobalTabCtrl, index, &rc)) {
                    // Safety: Precision hit-testing for the close button
                    if (hti.pt.x > rc.right - 25) {
                        RemoveTab(hwnd, index);
                    }
                }
            }
            return 0;
        }
    }
    break;
}

    case WM_COMMAND: {
        if (LOWORD(wParam) >= ID_RECENT_FOLDER_BASE &&
            LOWORD(wParam) <  ID_RECENT_FOLDER_BASE + MAX_RECENT_FOLDERS) {
            int index = LOWORD(wParam) - ID_RECENT_FOLDER_BASE;
            if (index < (int)g_RecentFolders.size()) {
                g_NextOpenDir = g_RecentFolders[index];
                DoFileOpen(hwnd);
                g_NextOpenDir = L"";
            }
            return 0;
        }

        if (LOWORD(wParam) == IDC_SYMBOL_LIST && HIWORD(wParam) == LBN_DBLCLK) {
            HWND hList = (HWND)lParam;
            int  sel   = (int)SendMessage(hList, LB_GETCURSEL, 0, 0);
            if (sel != LB_ERR && (size_t)sel < g_VisibleSymbols.size()) {
                const Symbol* pSym  = g_VisibleSymbols[sel];
                int           tabCount = TabCtrl_GetItemCount(hGlobalTabCtrl);
                for (int i = 0; i < tabCount; i++) {
                    TCITEM tcItem;
                    tcItem.mask = TCIF_PARAM;
                    TabCtrl_GetItem(hGlobalTabCtrl, i, &tcItem);
                    EditorTab* t = (EditorTab*)tcItem.lParam;
                    if (t && t->hEdit == pSym->hTab) {
                        TabCtrl_SetCurSel(hGlobalTabCtrl, i);
                        NMHDR nmhdr = { hGlobalTabCtrl, (UINT_PTR)IDC_MAIN_TAB, TCN_SELCHANGE };
                        SendMessage(hwnd, WM_NOTIFY, nmhdr.idFrom, (LPARAM)&nmhdr);
                        int charIdx = (int)SendMessage(t->hEdit, EM_LINEINDEX,
                                                       pSym->line - 1, 0);
                        SendMessage(t->hEdit, EM_SETSEL, charIdx, charIdx);
                        SendMessage(t->hEdit, EM_SCROLLCARET, 0, 0);
                        SetFocus(t->hEdit);
                        break;
                    }
                }
                if (g_hJumpMenuWnd && IsWindow(g_hJumpMenuWnd)) {
                    DestroyWindow(g_hJumpMenuWnd);
                    g_hJumpMenuWnd = NULL;
                }
            }
            return 0;
        }

        switch (LOWORD(wParam)) {
            case IDM_AUTOFILL_MANAGE:
                ShowAutofillManageDialog(hwnd);
                break;

            case IDM_EDIT_JUMP_SYMBOL: {
                globalSymbols.clear();
                EditorTab* active = GetActiveTab();
                if (active) RefreshSymbols(active->hEdit);
                ShowSymbolJumpMenu(hwnd);
                break;
            }

            case IDM_EDIT_MOVE_UP:
            case IDM_EDIT_MOVE_DOWN: {
                EditorTab* tab = GetActiveTab();
                if (!tab || !tab->hEdit) break;
                bool moveDown = (LOWORD(wParam) == IDM_EDIT_MOVE_DOWN);
                DWORD start, end;
                SendMessage(tab->hEdit, EM_GETSEL, (WPARAM)&start, (LPARAM)&end);
                int firstLine = (int)SendMessage(tab->hEdit, EM_LINEFROMCHAR, start, 0);

                if (!moveDown) {
                    if (firstLine <= 0) break;
                    int prevLine      = firstLine - 1;
                    int prevLineIndex = (int)SendMessage(tab->hEdit, EM_LINEINDEX, prevLine, 0);
                    int prevLineLen   = (int)SendMessage(tab->hEdit, EM_LINELENGTH,
                                                         prevLineIndex, 0);
                    if (prevLineLen > 0) {
                        std::unique_ptr<wchar_t[]> buffer(new wchar_t[prevLineLen + 1]);
                        *(WORD*)buffer.get() = (WORD)prevLineLen;
                        int copied = (int)SendMessage(tab->hEdit, EM_GETLINE,
                                                      prevLine, (LPARAM)buffer.get());
                        buffer[copied] = L'\0';
                        bool isColliding = false;
                        for (int ii = 0; ii < copied; ii++) {
                            if (buffer[ii] != L' ' && buffer[ii] != L'\t' &&
                                buffer[ii] != L'\r' && buffer[ii] != L'\n') {
                                isColliding = true;
                                break;
                            }
                        }
                        if (isColliding) {
                            MessageBox(hwnd,
                                L"No Further Retreat: The line above contains code.",
                                L"Collision", MB_OK | MB_ICONWARNING);
                            break;
                        }
                    }
                }

                SendMessage(tab->hEdit, WM_SETREDRAW, FALSE, 0);
                if (moveDown) {
                    int selStart = (int)SendMessage(tab->hEdit, EM_LINEINDEX, firstLine, 0);
                    SendMessage(tab->hEdit, EM_SETSEL, selStart, selStart);
                    EditCommand moveCommand = BeginReplaceCommand(tab->hEdit,
                        selStart, selStart, L"\r\n", start, end);
                    SendMessage(tab->hEdit, EM_REPLACESEL, TRUE, (LPARAM)L"\r\n");
                    start += 2; end += 2; firstLine++;
                    SendMessage(tab->hEdit, EM_SETSEL, start, end);
                    CommitEditCommand(tab, moveCommand, false);
                } else {
                    int prevLineIndex  = (int)SendMessage(tab->hEdit, EM_LINEINDEX,
                                                          firstLine - 1, 0);
                    int currentLineIdx = (int)SendMessage(tab->hEdit, EM_LINEINDEX,
                                                          firstLine, 0);
                    int charsToRemove  = currentLineIdx - prevLineIndex;
                    SendMessage(tab->hEdit, EM_SETSEL, prevLineIndex, currentLineIdx);
                    EditCommand moveCommand = BeginReplaceCommand(tab->hEdit,
                        prevLineIndex, currentLineIdx, L"", start, end);
                    SendMessage(tab->hEdit, EM_REPLACESEL, TRUE, (LPARAM)L"");
                    start -= charsToRemove;
                    end   -= charsToRemove;
                    firstLine--;
                    SendMessage(tab->hEdit, EM_SETSEL, start, end);
                    CommitEditCommand(tab, moveCommand, false);
                }
                SendMessage(tab->hEdit, EM_SETSEL, start, end);

                RECT rc;
                GetClientRect(tab->hEdit, &rc);
                int lineH = nCurrentFontSize;
                {
                    ScopedDC tmpDC(tab->hEdit);
                    if (tmpDC.isValid()) {
                        ScopedSelectObject selF(tmpDC, hEditorFont);
                        TEXTMETRIC tm;
                        GetTextMetrics(tmpDC, &tm);
                        if (tm.tmHeight > 0) lineH = tm.tmHeight;
                    }
                }
                int visLines   = (rc.bottom - rc.top) / lineH;
                int firstVis   = (int)SendMessage(tab->hEdit, EM_GETFIRSTVISIBLELINE, 0, 0);
                int targetScroll = firstLine - (visLines / 2);
                SendMessage(tab->hEdit, EM_LINESCROLL, 0, targetScroll - firstVis);

                SendMessage(tab->hEdit, WM_SETREDRAW, TRUE, 0);
                InvalidateRect(tab->hEdit, NULL, TRUE);
                return 0;
            }

            case ID_GOTO_ERROR: {
                EditorTab* tab = GetActiveTab();
                if (tab && tab->errorLine > 0) {
                    int charIdx = (int)SendMessage(tab->hEdit, EM_LINEINDEX,
                                                   tab->errorLine - 1, 0);
                    if (charIdx != -1) {
                        SetFocus(tab->hEdit);
                        SendMessage(tab->hEdit, EM_SETSEL,      charIdx, charIdx);
                        SendMessage(tab->hEdit, EM_SCROLLCARET, 0, 0);
                    }
                }
                break;
            }

            case IDM_EDIT_INDENT: {
                EditorTab* active = GetActiveTab();
                if (active) HandleBlockIndent(active->hEdit, false);
                break;
            }
            case IDM_EDIT_OUTDENT: {
                EditorTab* active = GetActiveTab();
                if (active) HandleBlockIndent(active->hEdit, true);
                break;
            }
            case IDM_PURGE_TAB_RAM: PurgeActiveTabRam(hwnd); break;

            case IDM_EDIT_COMPACT:
                                OnEditCompact(hwnd);
                                break;

            case IDM_FOCUS_EDITOR: {
                EditorTab* active = GetActiveTab();
                if (active && active->hEdit) {
                    SetFocus(active->hEdit);
                    int len = GetWindowTextLength(active->hEdit);
                    SendMessage(active->hEdit, EM_SETSEL, len, len);
                }
                break;
            }
            case IDM_FOCUS_CMD:
                SetFocus(hCmdInput);
                SendMessage(hCmdInput, EM_SETSEL, -1, -1);
                break;
            case IDM_FOCUS_SEARCH:
                SetFocus(hSearchInput);
                SendMessage(hSearchInput, EM_SETSEL, -1, -1);
                break;

            case IDM_EDIT_SELECT_J: {
                HWND hFocused = GetFocus();
                if (hFocused == hCmdInput || hFocused == hSearchInput)
                    SendMessage(hFocused, EM_SETSEL, 0, -1);
                break;
            }

            case IDM_FILE_NEW:    CreateNewTab(hwnd); break;
            case IDM_FILE_OPEN:   DoFileOpen(hwnd);   break;
            case IDM_FILE_SAVE:   DoFileSave(hwnd);   break;
            case IDM_FILE_SAVEAS: DoFileSaveAs(hwnd);  break;
            case IDM_FILE_EXIT:   SendMessage(hwnd, WM_CLOSE, 0, 0); break;

            case IDC_NEW_FOLDER_BTN:
                SidebarCreateFolder(hwnd);
                break;

            case IDC_EXECUTE_BTN: {
                EditorTab* active = GetActiveTab();
                if (!active) break;
                if (GetWindowTextLength(hCmdInput) == 0) {
                    MessageBox(hwnd, L"Please enter a command.", L"Warning", MB_OK);
                    SetFocus(hCmdInput);
                } else {
                    if (active->bModified || active->sFilePath.empty())
                        DoFileSave(hwnd);
                    if (!active->sFilePath.empty())
                        DoExecuteFile(hwnd, hCmdInput);
                }
                break;
            }
            case IDC_CHECK_BTN: {
                EditorTab* active = GetActiveTab();
                if (!active) break;
                if (GetWindowTextLength(hCmdInput) == 0) {
                    MessageBox(hwnd, L"Please enter a command.", L"Warning", MB_OK);
                    SetFocus(hCmdInput);
                } else {
                    DoCheckSyntaxAsync(hwnd, hCmdInput);
                }
                break;
            }
            case IDC_SEARCH_BTN:    DoSearchText(hwnd, hSearchInput, false); break;
            case IDC_SEARCH_UP_BTN: DoSearchText(hwnd, hSearchInput, true);  break;

            case IDC_SYNTAX_TOGGLE: {
                g_SyntaxHighlighting = !g_SyntaxHighlighting;
                SetWindowText(hSyntaxBtn,
                              g_SyntaxHighlighting ? L"SYN: ON" : L"SYN: OFF");
                for (auto& up : g_Tabs) {
                    EditorTab* t = up.get();
                    if (!t) continue;
                    InvalidateRect(t->hEdit,   NULL, TRUE);
                    InvalidateRect(t->hGutter, NULL, TRUE);
                }
                break;
            }

            case IDC_SIDEBAR_TOGGLE: {
                // Toggle sidebar visibility. The drag-resize path is blocked when
                // g_sidebarVisible == false, so this button is the only way to hide.
                g_sidebarVisible = !g_sidebarVisible;

                if (g_sidebarVisible) {
                    // Show: restore last saved non-zero width.
                    if (g_savedSidebarWidth < SIDEBAR_MIN_WIDTH)
                        g_savedSidebarWidth = SIDEBAR_DEFAULT_WIDTH;
                    g_sidebarWidth = g_savedSidebarWidth;
                } else {
                    // Hide: remember the current open width for next show.
                    if (g_sidebarWidth > 0)
                        g_savedSidebarWidth = g_sidebarWidth;
                    g_sidebarWidth = 0;
                }

                // Update button label immediately.
                if (g_hSidebarToggleBtn && IsWindow(g_hSidebarToggleBtn))
                    SetWindowText(g_hSidebarToggleBtn,
                        g_sidebarVisible ? L"\u25c0 Tree" : L"Tree \u25b6");

                // Force a full layout pass — repositions tree, splitter, and editor.
                {
                    RECT rc;
                    GetClientRect(hwnd, &rc);
                    SendMessage(hwnd, WM_SIZE, SIZE_RESTORED,
                                MAKELPARAM(rc.right, rc.bottom));
                }

                // MoveWindow the active tab's hEdit to force an immediate repaint
                // (belt-and-suspenders: DeferWindowPos already moved it above, but
                //  MoveWindow issues a WM_MOVE + WM_SIZE to the control itself).
                EditorTab* activeTab = GetActiveTab();
                if (activeTab && activeTab->hEdit && IsWindow(activeTab->hEdit)) {
                    RECT rcEdit;
                    GetWindowRect(activeTab->hEdit, &rcEdit);
                    MapWindowPoints(NULL, hwnd, (LPPOINT)&rcEdit, 2);
                    MoveWindow(activeTab->hEdit,
                               rcEdit.left, rcEdit.top,
                               rcEdit.right - rcEdit.left,
                               rcEdit.bottom - rcEdit.top, TRUE);
                }
                if (g_hDirTree && IsWindow(g_hDirTree)) {
                    RECT rcTree;
                    GetWindowRect(g_hDirTree, &rcTree);
                    MapWindowPoints(NULL, hwnd, (LPPOINT)&rcTree, 2);
                    MoveWindow(g_hDirTree,
                               rcTree.left, rcTree.top,
                               rcTree.right  - rcTree.left,
                               rcTree.bottom - rcTree.top, TRUE);
                }

                // Persist the new state.
                SaveSidebarWidth();
                break;
            }
        }

        if (LOWORD(wParam) == IDC_MAIN_EDIT && HIWORD(wParam) == EN_CHANGE) {
            EditorTab* tab = GetActiveTab();
            if (tab) {
                // v20: Suppress all EN_CHANGE-driven work while a bulk
                // file load is streaming chunks into the editor. Each
                // EM_REPLACESEL fires EN_CHANGE; doing line counts /
                // word counts / syntax recolor per chunk would re-walk
                // the entire (growing) buffer ~N times and turn an
                // O(N) load into O(N^2). The WM_FILE_LOAD_COMPLETE
                // handler runs all these readouts exactly once after
                // the bulk insert finishes.
                if (g_bBulkLoading.load(std::memory_order_acquire)) {
                    return 0;
                }

                // v4.32 TYPING-LAG FIX — coalesce per-keystroke heavy work.
                //
                // The old path ran, on EVERY keystroke:
                //   * UpdateLineCount   (walks the buffer)
                //   * tab->GetDocument()  + SpawnStatsWorker  (COPIES the
                //     entire document into a wstring, every keystroke)
                //   * UpdateGutter / UpdateColInfo / UpdatePieceCount
                //   * EM_GETLINECOUNT (walks the buffer)
                //   * InvalidateRect on the gutter
                //
                // On a multi-MB log this is the dominant typing-lag source —
                // each keystroke duplicates the whole document and re-walks
                // it, so a 100 ms keyrepeat backlogs into seconds.
                //
                // We now ALWAYS update cheap state immediately (dirty flag,
                // title, error-line clear, cachedDocDirty) so correctness /
                // undo / save behaviour is unchanged, and we kick a 16 ms
                // one-shot WM_TIMER that runs the heavy readouts at most
                // once per frame regardless of typing speed.
                tab->cachedDocDirty = true;
                if (!tab->bModified) { tab->bModified = true; UpdateTitle(hwnd); }
                tab->errorLine = -1;

                // Coalesce: SetTimer with the same id just resets the
                // interval, so a fast burst of keystrokes collapses into
                // exactly one heavy-work pass after the typing pauses for
                // ~16 ms (one frame at 60 Hz).
                SetTimer(hwnd, IDT_EN_CHANGE_COALESCE, 16, NULL);
            }
        }
        break;
    }

    case WM_TIMER: {
        // v4.32 — coalesced EN_CHANGE drain. Runs the heavy per-edit
        // readouts that used to fire on every keystroke. One-shot:
        // KillTimer immediately so we don't tick again until the next
        // EN_CHANGE re-arms it.
        if (wParam == IDT_EN_CHANGE_COALESCE) {
            KillTimer(hwnd, IDT_EN_CHANGE_COALESCE);
            // v4.35 S5 — drain wrapped in try/catch so a transient
            // std::bad_alloc inside the worker spawn or a stale tab
            // pointer dereference cannot tear the message loop down
            // and lose the user's unsaved work.
            try {
                EditorTab* tab = GetActiveTab();
                if (tab && TF_Safety::WindowAlive(tab->hEdit) &&
                    !g_bBulkLoading.load(std::memory_order_acquire))
                {
                    UpdateLineCount(tab->hEdit, hGlobalLineCount);
                    UpdateColInfo(tab->hEdit);
                    UpdatePieceCount(tab);
                    UpdateGutter(tab->hEdit, tab->hGutter);

                    size_t docChars = tab->pt.Length();
                    if (TF_Safety::MulSatSizeT(docChars, sizeof(wchar_t)) <= TF_STATS_FAST_PATH_BYTES) {
                        SpawnStatsWorker(hwnd,
                                         tab->hEdit,
                                         hGlobalWordCount,
                                         hGlobalCharCount,
                                         tab->GetDocument());
                    } else {
                        SetTimer(hwnd, IDT_STATS_DEFER_COALESCE, 250, NULL);
                    }

                    int count = (int)SendMessage(tab->hEdit, EM_GETLINECOUNT, 0, 0);
                    int d1 = 1, t1 = count;
                    while (t1 >= 10) { t1 /= 10; d1++; }
                    int d2 = 1, t2 = tab->lastLineCount;
                    while (t2 >= 10) { t2 /= 10; d2++; }
                    if (d1 != d2) {
                        SetTimer(hwnd, IDT_GUTTER_LAYOUT_DEFER, 100, NULL);
                    }
                    tab->lastLineCount = count;
                }
            } catch (...) {
                // Swallow — never let the UI thread die on a coalescer drain.
            }
            return 0;
        }

        // v4.34 — deferred stats for huge documents (v4.35: try/catch wrapped).
        if (wParam == IDT_STATS_DEFER_COALESCE) {
            KillTimer(hwnd, IDT_STATS_DEFER_COALESCE);
            try {
                EditorTab* tab = GetActiveTab();
                if (tab && TF_Safety::WindowAlive(tab->hEdit) &&
                    !g_bBulkLoading.load(std::memory_order_acquire))
                {
                    SpawnStatsWorker(hwnd,
                                     tab->hEdit,
                                     hGlobalWordCount,
                                     hGlobalCharCount,
                                     tab->GetDocument());
                }
            } catch (...) {
                // Swallow — see S5 rationale above.
            }
            return 0;
        }

        // v4.34 — debounced gutter-digit relayout (v4.35: try/catch wrapped).
        if (wParam == IDT_GUTTER_LAYOUT_DEFER) {
            KillTimer(hwnd, IDT_GUTTER_LAYOUT_DEFER);
            try {
                if (TF_Safety::WindowAlive(hwnd)) {
                    RECT rc;
                    GetClientRect(hwnd, &rc);
                    PostMessage(hwnd, WM_SIZE, 0, MAKELPARAM(rc.right, rc.bottom));
                }
            } catch (...) {
                // Swallow.
            }
            return 0;
        }
        break;
    }

    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, TEXT_COLOR);
        SetBkColor(hdc, BG_COLOR);
        return (LRESULT)hBackBrush;
    }

    case WM_SIZE: {
        int w = LOWORD(lParam), h = HIWORD(lParam);
        if (w == 0 || h == 0) break;
        // v19: keep the async-load overlay anchored above the bottom toolbar.
        LayoutLoadProgressPanel(hwnd);
        int th = 32, bh = 75;

        // Determine effective sidebar width: auto-collapse only if the window
        // itself is narrower than sidebar+editor minimum — never override a user
        // drag that already collapsed it (g_sidebarVisible == false).
        int sideW      = g_sidebarVisible ? g_sidebarWidth : 0;
        int splitterW  = (sideW > 0) ? SPLITTER_WIDTH : 0; // hide splitter when collapsed
        int editorLeft = sideW + splitterW;
        int editorW    = w - editorLeft;
        if (editorW < 100) {
            // Window genuinely too narrow: auto-hide sidebar (don't change g_sidebarVisible).
            sideW      = 0;
            splitterW  = 0;
            editorLeft = 0;
            editorW    = w;
        }

        bool showStatus = (w > 600);

        HWND statusCtrls[] = {
            hGlobalLineCount, hGlobalWordCount, hGlobalCharCount,
            hGlobalColInfo, hGlobalPieceCount };
        for (HWND ctrl : statusCtrls)
            ShowWindow(ctrl, showStatus ? SW_SHOW : SW_HIDE);

        int treeH = h - th - bh;
        if (treeH < 0) treeH = 0;
        int sidebarToolbarH = (sideW > 0) ? SIDEBAR_TOOLBAR_HEIGHT : 0;
        int treeY = th + sidebarToolbarH;
        int visibleTreeH = treeH - sidebarToolbarH;
        if (visibleTreeH < 0) visibleTreeH = 0;

        int lineCount = 1;
        EditorTab* active = GetActiveTab();
        if (active) lineCount = (int)SendMessage(active->hEdit, EM_GETLINECOUNT, 0, 0);
        int digits = 1, tempCount = lineCount;
        while (tempCount >= 10) { tempCount /= 10; digits++; }
        if (digits < 3) digits = 3;

        {
            ScopedDC hdc(hwnd);
            if (hdc.isValid()) {
                ScopedSelectObject selFont(hdc, hEditorFont);
                SIZE sz;
                GetTextExtentPoint32(hdc, L"0", 1, &sz);
                int gw = (digits * sz.cx) + 20;

                int statusWidth    = showStatus ? 120 : 0;
                int pieceWidth     = showStatus ? 120 : 0;
                int statusGap      = showStatus ? 8 : 0;
                int labelWidth     = 80;
                int checkBtnWidth  = 80;
                int execBtnWidth   = 90;
                int syntaxBtnWidth = 90;
                int availableWidth = w - labelWidth - checkBtnWidth - execBtnWidth
                                   - statusWidth - pieceWidth - statusGap - 40;
                int inputWidth     = (availableWidth < 100) ? 100 : availableWidth;

                int editHeight = h - bh - th;
                // Batch ALL child window moves in one DeferWindowPos call to prevent
                // intermediate repaints and the "lag" seen in naive Win32 layouts.
                int nDeferred = (int)g_Tabs.size() * 2 + 19; // tabs + sidebar + splitter + controls
                HDWP hdwp = BeginDeferWindowPos(nDeferred);

                // 1. Sidebar action strip + TreeView
                if (g_hNewFolderBtn && IsWindow(g_hNewFolderBtn)) {
                    hdwp = DeferWindowPos(hdwp, g_hNewFolderBtn, NULL,
                                          4, th + 4,
                                          sideW > 8 ? sideW - 8 : 0, 24,
                                          SWP_NOZORDER |
                                          (sideW > 0 ? SWP_SHOWWINDOW : SWP_HIDEWINDOW));
                }

                if (g_hDirTree && IsWindow(g_hDirTree)) {
                    hdwp = DeferWindowPos(hdwp, g_hDirTree, NULL,
                                          0, treeY, sideW, visibleTreeH,
                                          SWP_NOZORDER |
                                          (sideW > 0 ? SWP_SHOWWINDOW : SWP_HIDEWINDOW));
                }

                // 2. Splitter bar
                if (g_hSplitter && IsWindow(g_hSplitter)) {
                    hdwp = DeferWindowPos(hdwp, g_hSplitter, NULL,
                                          sideW, th, splitterW, treeH,
                                          SWP_NOZORDER |
                                          (splitterW > 0 ? SWP_SHOWWINDOW : SWP_HIDEWINDOW));
                }

                // 3. Tab bar — full window width.
                hdwp = DeferWindowPos(hdwp, hGlobalTabCtrl, NULL,
                                      0, 0, w, 28, SWP_NOZORDER);

                // 4. Per-tab gutter + edit.
                for (int i = 0; i < (int)g_Tabs.size(); i++) {
                    int showCmd = (i == g_ActiveTabIndex)
                                  ? SWP_SHOWWINDOW : SWP_HIDEWINDOW;
                    hdwp = DeferWindowPos(hdwp, g_Tabs[i]->hGutter, NULL,
                                          editorLeft,      th,
                                          gw,              editHeight,
                                          SWP_NOZORDER | showCmd);
                    hdwp = DeferWindowPos(hdwp, g_Tabs[i]->hEdit, NULL,
                                          editorLeft + gw, th,
                                          editorW - gw,    editHeight,
                                          SWP_NOZORDER | showCmd);
                }

                // 5. Bottom control strip.
                int row1Y = h - bh + 5, row2Y = h - bh + 40;
                hdwp = DeferWindowPos(hdwp, hLbl,      NULL,
                                      5, row1Y, labelWidth, 25, SWP_NOZORDER);
                hdwp = DeferWindowPos(hdwp, hCmdInput, NULL,
                                      labelWidth + 10, row1Y - 3, inputWidth, 25,
                                      SWP_NOZORDER);
                hdwp = DeferWindowPos(hdwp, hCheckBtn, NULL,
                                      labelWidth + inputWidth + 20, row1Y - 5,
                                      checkBtnWidth, 30, SWP_NOZORDER);
                hdwp = DeferWindowPos(hdwp, hExecBtn,  NULL,
                                      labelWidth + inputWidth + checkBtnWidth + 25,
                                      row1Y - 5, execBtnWidth, 30, SWP_NOZORDER);

                // Toggle button: always visible; sits above the piece count column.
                // Update its label to reflect the current sidebar state.
                if (g_hSidebarToggleBtn && IsWindow(g_hSidebarToggleBtn)) {
                    SetWindowText(g_hSidebarToggleBtn,
                        g_sidebarVisible ? L"\u25c0 Tree" : L"Tree \u25b6");
                }

                if (showStatus) {
                    int rightStatusX = w - statusWidth - 5;
                    int pieceStatusX = rightStatusX - statusGap - pieceWidth;
                    hdwp = DeferWindowPos(hdwp, hGlobalLineCount, NULL,
                                          rightStatusX, row1Y - 5,
                                          statusWidth, 20, SWP_NOZORDER);
                    hdwp = DeferWindowPos(hdwp, hGlobalWordCount, NULL,
                                          rightStatusX, row1Y + 12,
                                          statusWidth, 20, SWP_NOZORDER);
                    hdwp = DeferWindowPos(hdwp, hGlobalPieceCount, NULL,
                                          pieceStatusX, row2Y + 12,
                                          pieceWidth, 20, SWP_NOZORDER);

                    // Toggle button sits directly above the piece count label.
                    if (g_hSidebarToggleBtn && IsWindow(g_hSidebarToggleBtn)) {
                        hdwp = DeferWindowPos(hdwp, g_hSidebarToggleBtn, NULL,
                                              pieceStatusX, row1Y - 5,
                                              pieceWidth, 25,
                                              SWP_NOZORDER | SWP_SHOWWINDOW);
                    }
                } else {
                    // Status panel hidden — park toggle at far right so it stays reachable.
                    if (g_hSidebarToggleBtn && IsWindow(g_hSidebarToggleBtn)) {
                        hdwp = DeferWindowPos(hdwp, g_hSidebarToggleBtn, NULL,
                                              w - 90, row1Y - 5, 80, 25,
                                              SWP_NOZORDER | SWP_SHOWWINDOW);
                    }
                }

                hdwp = DeferWindowPos(hdwp, hSearchLbl,   NULL,
                                      5, row2Y, labelWidth, 25, SWP_NOZORDER);
                hdwp = DeferWindowPos(hdwp, hSearchInput, NULL,
                                      labelWidth + 10, row2Y - 3, inputWidth, 25,
                                      SWP_NOZORDER);
                hdwp = DeferWindowPos(hdwp, hSearchBtn,   NULL,
                                      labelWidth + inputWidth + 20, row2Y - 5,
                                      40, 30, SWP_NOZORDER);
                hdwp = DeferWindowPos(hdwp, hSearchUpBtn, NULL,
                                      labelWidth + inputWidth + 65, row2Y - 5,
                                      35, 30, SWP_NOZORDER);
                hdwp = DeferWindowPos(hdwp, hSyntaxBtn,   NULL,
                                      labelWidth + inputWidth + checkBtnWidth + 25,
                                      row2Y - 5, syntaxBtnWidth, 30, SWP_NOZORDER);

                if (showStatus) {
                    int rightStatusX = w - statusWidth - 5;
                    hdwp = DeferWindowPos(hdwp, hGlobalCharCount, NULL,
                                          rightStatusX, row2Y - 5,
                                          statusWidth, 20, SWP_NOZORDER);
                    hdwp = DeferWindowPos(hdwp, hGlobalColInfo,   NULL,
                                          rightStatusX, row2Y + 12,
                                          statusWidth, 20, SWP_NOZORDER);
                }

                EndDeferWindowPos(hdwp);
            }
        }
        break;
    }

    case WM_GETMINMAXINFO: {
        MINMAXINFO* mmi = (MINMAXINFO*)lParam;
        mmi->ptMinTrackSize.x = 480;
        mmi->ptMinTrackSize.y = 360;
        return 0;
    }

    case WM_CLOSE: {
        // ── v4.39 SAFE-CLOSE-WHILE-LOADING ──────────────────────────────
        // Step 1: raise BOTH cancel flags BEFORE we walk g_Tabs or call
        // PromptForSave (which itself pumps messages).  This guarantees
        // that any BulkSetEditText currently on the call stack — possibly
        // the very pump that delivered this WM_CLOSE — exits at its next
        // per-chunk gate instead of running another EM_REPLACESEL after
        // we've started destroying tabs.
        g_appQuitRequested.store(true, std::memory_order_release);
        g_bBulkLoadCancel.store(true, std::memory_order_release);

        // Step 2: drain messages briefly so any in-flight BulkSetEditText
        // has a chance to unwind.  Bounded (~3 s) so a hung worker can't
        // freeze the close.  We watch g_hBulkLoadingEdit drop to NULL.
        for (int spin = 0; spin < 300; ++spin) {
            if (g_hBulkLoadingEdit.load(std::memory_order_acquire) == NULL)
                break;
            MSG m;
            for (int i = 0; i < 32 && PeekMessageW(&m, NULL, 0, 0, PM_REMOVE); ++i) {
                if (m.message == WM_QUIT) {
                    PostQuitMessage((int)m.wParam);
                    DestroyWindow(hwnd);
                    return 0;
                }
                TranslateMessage(&m);
                DispatchMessageW(&m);
            }
            Sleep(10);
        }

        // Step 3: now it's safe to prompt-for-save.  Skip tabs that are
        // still mid-async-load (no user content to lose) so we do not
        // ask "save your hourglass tab?" — the cancel flags above have
        // already torn down any render in progress.
        bool cancel = false;
        // v4.45: snapshot raw pointers from the unique_ptr vector so we can
        // iterate safely even if PromptForSave/DoFileSave mutate g_Tabs.
        std::vector<EditorTab*> snapshot;
        snapshot.reserve(g_Tabs.size());
        for (auto& up : g_Tabs) snapshot.push_back(up.get());
        for (EditorTab* t : snapshot) {
            if (!t)               continue;
            // Re-verify the tab still lives in g_Tabs (could have been closed
            // by a reentrant message during a previous PromptForSave).
            int curIdx = -1;
            for (size_t i = 0; i < g_Tabs.size(); ++i) {
                if (g_Tabs[i].get() == t) { curIdx = (int)i; break; }
            }
            if (curIdx < 0)        continue;
            if (t->bAsyncLoading)  continue;   // v4.39: nothing to save yet
            int c = PromptForSave(hwnd, t);
            if (c == 1) {
                int old = g_ActiveTabIndex;
                g_ActiveTabIndex = curIdx;
                DoFileSave(hwnd);
                g_ActiveTabIndex = old;
            } else if (c == -1) {
                // User cancelled the close.  Clear the quit flags so the
                // app keeps running normally — including any future loads.
                g_appQuitRequested.store(false, std::memory_order_release);
                g_bBulkLoadCancel.store(false, std::memory_order_release);
                cancel = true;
                break;
            }
        }
        if (!cancel) DestroyWindow(hwnd);
        break;
    }

    case WM_UPDATE_STATS: {
        // v4.12 doorbell: drain g_StatResultQueue. Apply each result only if:
        //   (a) its hEdit still belongs to the currently active tab, AND
        //   (b) its seq is newer than anything we've already applied for hEdit.
        // Stale results (older keystrokes, or for tabs the user has switched
        // away from) are silently discarded. Label HWNDs are revalidated with
        // IsWindow() because the user could close a tab between push and pop.
        EditorTab* active = GetActiveTab();
        const HWND activeEdit = active ? active->hEdit : nullptr;

        while (auto r = g_StatResultQueue.try_pop()) {
            if (!r) break;
            uint64_t& last = g_StatLastApplied[r->hEdit];
            if (r->seq <= last) continue;     // stale, drop
            last = r->seq;

            if (r->hEdit != activeEdit) continue;   // not visible tab; drop quietly

            if (r->hWordLabel && IsWindow(r->hWordLabel)) {
                wchar_t buf[64];
                swprintf_s(buf, 64, L"Words: %d", r->wordCount);
                SendMessageW(r->hWordLabel, WM_SETTEXT, 0, (LPARAM)buf);
                InvalidateRect(r->hWordLabel, NULL, TRUE);
            }
            if (r->hCharLabel && IsWindow(r->hCharLabel)) {
                wchar_t buf[64];
                swprintf_s(buf, 64, L"Chars: %d", r->charCount);
                SendMessageW(r->hCharLabel, WM_SETTEXT, 0, (LPARAM)buf);
                InvalidateRect(r->hCharLabel, NULL, TRUE);
            }
        }

        // Opportunistic GC of the per-edit map.
        if (g_StatLastApplied.size() > 256) {
            for (auto it = g_StatLastApplied.begin(); it != g_StatLastApplied.end(); ) {
                if (!IsWindow(it->first)) it = g_StatLastApplied.erase(it);
                else                      ++it;
            }
        }
        return 0;
    }

    case WM_FILE_REMOVED: {
        // v4.11: lParam is a null doorbell — paths are in g_FileRemovedQueue.
        // HandleFileRemovedMessage() drains the queue with try_pop().
        // No raw pointer ownership; the queue entry is a std::wstring value.
        HandleFileRemovedMessage();
        return 0;
    }

    case WM_SIDEBAR_REFRESH: {
        // v4.15: coalesced add/rename/dir-change sidebar rescan.
        // HandleSidebarRefreshMessage() clears g_SidebarRefreshPending first
        // (so the watcher thread can re-arm immediately), then issues an async
        // SidebarLoadDirectory that preserves the current tree selection.
        HandleSidebarRefreshMessage(hwnd);
        return 0;
    }

    case WM_TF_UI_TASK: {
        // v4.26: Drain g_UITaskQueue and execute every queued std::function
        // on the UI thread.  Each task is wrapped in try/catch so a single
        // misbehaving worker cannot tear down the message pump.  We always
        // drain the entire queue per doorbell so a coalesced doorbell (one
        // posted while another was in flight) cannot leave tasks stranded.
        for (;;) {
            auto task = g_UITaskQueue.try_pop();
            if (!task) break;
            if (!task) continue;
            try {
                (task)();
            } catch (...) {
                // Swallow — UI thread MUST keep pumping. Worker bugs do not
                // get to crash the editor.
            }
        }
        return 0;
    }

    case WM_DESTROY: {
        // ── v4.11 FORMALIZED SHUTDOWN PROTOCOL ────────────────────────────
        // Phase 1: Signal all background threads to stop.
        //   FileWatcherStop() signals hShutdown + CancelIoEx so the watcher
        //   thread unblocks from WaitForMultipleObjects immediately.
        //   g_ThreadMgr.shutdownAll() then:
        //     • Sets g_appRunning = false  (threads poll this flag).
        //     • Calls shutdown() on every queue (wakes any blocked push/wait_pop).
        //     • Joins every std::thread we spawned (LIFO order).
        //   No worker can touch UI state after this point.
        // ─────────────────────────────────────────────────────────────────
        // v4.32 — kill the EN_CHANGE coalescing timer BEFORE we destroy
        // workers. Belt-and-braces: a stray WM_TIMER fire after the
        // active tab is gone would noop (the handler re-checks tab/IsWindow),
        // but cancelling here avoids the spurious post entirely.
        // v4.34: same treatment for the deferred-stats / layout-debounce timers.
        KillTimer(hwnd, IDT_EN_CHANGE_COALESCE);
        KillTimer(hwnd, IDT_STATS_DEFER_COALESCE);
        KillTimer(hwnd, IDT_GUTTER_LAYOUT_DEFER);

        // v4.41: kill the autosave heartbeat first; a stray WM_TIMER
        // dispatched after this point would race the tab vector teardown.
        tf_v441::Reliability::StopAutosaveTimer(hwnd);

        FileWatcherStop();          // signal watcher; join happens in shutdownAll()
        g_ThreadMgr.shutdownAll();  // joins ALL threads (file load, syntax, dir, watcher)

        // Phase 2: Drain any leftover queue items so no unique_ptrs leak.
        while (g_FileLoadQueue.try_pop())       {}
        while (g_FileLoadFailedQueue.try_pop()) {}
        while (g_SyntaxCheckQueue.try_pop())    {}
        while (g_DirLoadQueue.try_pop())             {}
        while (!g_FileRemovedQueue.try_pop().empty()) {} // wstring, drain silently
        while (g_StatResultQueue.try_pop())     {}       // v4.12: stats results
        while (g_UITaskQueue.try_pop())         {}       // v4.26: marshalled UI tasks
        g_StatLastApplied.clear();                       // v4.12
        g_SidebarRefreshPending.store(false);            // v4.15: clear pending refresh flag
        g_hMainWnd.store(nullptr, std::memory_order_release); // v4.26: workers see "no UI"

        // Phase 3: Tear down UI and heap state.
        HideAutofillPopup();
        g_AutofillWords.clear();

        // v4.28: tear down the async-load progress overlay through the
        // dedicated helper.  This (a) destroys the panel HWND tree (which
        // implicitly destroys the label + bar children, releasing their
        // USER32 + GDI objects), (b) clears the per-load registry so any
        // late doorbell that somehow survives the queue drain becomes a
        // safe no-op, and (c) zeros g_ActiveLoads.  Idempotent.
        DestroyLoadProgressUI();

        // Tear down the sidebar tree.  Path payloads are owned by g_TreeMap
        // (not by lParam pointers) so we simply clear the map alongside the
        // tree itself.  SidebarFreeTreeItemData is a retained no-op kept
        // strictly for ABI compatibility with any external callers.
        if (g_hDirTree && IsWindow(g_hDirTree)) {
            TreeView_DeleteAllItems(g_hDirTree);
            g_hDirTree = NULL;
        }
        g_TreeMap.clear();
        g_TreeRootDir.clear();
        // Splitter bar is a child window; destroyed by DestroyWindow(hwnd), but null it anyway.
        g_hSplitter = NULL;
        // Persist sidebar width on clean exit.
        SaveSidebarWidth();

        if (hEditorFont)  { DeleteObject(hEditorFont);  hEditorFont  = NULL; }
        if (hUIFont)      { DeleteObject(hUIFont);      hUIFont      = NULL; }
        if (hBackBrush)   { DeleteObject(hBackBrush);   hBackBrush   = NULL; }
        if (hGutterBrush) { DeleteObject(hGutterBrush); hGutterBrush = NULL; }
        if (hDotBrush)    { DeleteObject(hDotBrush);    hDotBrush    = NULL; }
        if (hMatchBrush)  { DeleteObject(hMatchBrush);  hMatchBrush  = NULL; }

        // v4.44 O1: destroy windows + clear payload, then let unique_ptr
        // destructors run via .clear().  No raw `delete` anywhere.
        for (auto& up : g_Tabs) {
            EditorTab* t = up.get();
            if (!t) continue;
            t->lifecycle.store((uint8_t)TabLifecycle::Dead, std::memory_order_release);
            t->loadId = 0;
            TF_UnregisterTab(t);
            ClearTabRamPayload(t, true, true);
            if (t->hEdit   && IsWindow(t->hEdit))   DestroyWindow(t->hEdit);
            if (t->hGutter && IsWindow(t->hGutter)) DestroyWindow(t->hGutter);
        }
        g_Tabs.clear();   // unique_ptr destructors run for every slot
        for (auto& up : g_AbandonedLoadingTabs) {
            EditorTab* t = up.get();
            if (!t) continue;
            t->lifecycle.store((uint8_t)TabLifecycle::Dead, std::memory_order_release);
            t->loadId = 0;
            TF_UnregisterTab(t);
            ClearTabRamPayload(t, true, true);
            if (t->hEdit   && IsWindow(t->hEdit))   DestroyWindow(t->hEdit);
            if (t->hGutter && IsWindow(t->hGutter)) DestroyWindow(t->hGutter);
        }
        g_AbandonedLoadingTabs.clear();   // unique_ptr destructors run
        g_AbandonedLoadIds.clear();
        globalSymbols.clear();
        g_VisibleSymbols.clear();
        TrimProcessRamNow();

        PostQuitMessage(0);
        break;
    }

    default:
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}



// =============================================================================
//  v4.41 — SEH-guarded WindowProc wrapper.
//
//  Wraps every dispatch in a structured-exception filter so an access
//  violation, stack overflow, or bad-pointer dereference inside ANY
//  handler triggers an emergency flush of every modified tab to a
//  .recover snapshot before the OS terminates the process.  The next
//  launch surfaces those snapshots via ScanForRecoverySnapshotsOnStartup.
//
//  We do NOT swallow the exception — that would leave the process in
//  an unknown state.  We let it propagate so the OS still tears us
//  down (and so a debugger still catches it).  The only contract this
//  wrapper adds is: "no matter what, the user does not lose unsaved
//  work to a hard crash."
// =============================================================================
//
// Portability note (v4.41a):
//   __try / __except is MSVC-only Structured Exception Handling.  When the
//   project is compiled with GCC/MinGW (g++) those keywords don't exist
//   and the file fails to parse.  We therefore split the wrapper into two
//   compile-time branches:
//
//     * MSVC      — keep real SEH so we catch hardware faults
//                   (access violations, stack overflow, /0) AND C++
//                   exceptions, flush recovery snapshots, then let the
//                   OS tear us down via EXCEPTION_CONTINUE_SEARCH.
//
//     * GCC/MinGW — use a C++ try/catch for thrown exceptions, AND a
//                   process-wide Vectored Exception Handler (installed
//                   once in WinMain) so hardware faults still trigger
//                   CrashFlushAllTabs before the process dies.
//
// Either way the contract is identical: "no matter what, the user does
// not lose unsaved work to a hard crash."
// =============================================================================
#if defined(_MSC_VER)
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    __try {
        return WindowProcImpl(hwnd, uMsg, wParam, lParam);
    }
    __except ( (tf_v441::Reliability::CrashFlushAllTabs(), EXCEPTION_CONTINUE_SEARCH) ) {
        return 0;   // unreachable — filter returns CONTINUE_SEARCH
    }
}
#else
// GCC/MinGW path: C++ try/catch covers thrown exceptions; the Vectored
// Exception Handler installed in WinMain covers hardware faults.
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    try {
        return WindowProcImpl(hwnd, uMsg, wParam, lParam);
    } catch (...) {
        // Flush every modified tab to a .recover file, then re-throw so
        // the outer runtime / OS still terminates the process — we do not
        // want to keep running in an unknown state.
        tf_v441::Reliability::CrashFlushAllTabs();
        throw;
    }
}

// Vectored Exception Handler — fires for hardware-level SEH exceptions
// (EXCEPTION_ACCESS_VIOLATION, EXCEPTION_STACK_OVERFLOW, etc.) regardless
// of which compiler built us.  We flush recovery snapshots and then
// return EXCEPTION_CONTINUE_SEARCH so the default unhandled-exception
// path still runs (debugger break, WER, process termination).
static LONG CALLBACK Tf_CrashVEH(EXCEPTION_POINTERS* pExc) noexcept {
    if (!pExc || !pExc->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    const DWORD code = pExc->ExceptionRecord->ExceptionCode;
    // Only react to genuinely fatal codes — ignore C++ throw markers
    // (0xE06D7363) and DLL-load notifications.  The C++ try/catch above
    // already handles thrown exceptions.
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION:
        case EXCEPTION_STACK_OVERFLOW:
        case EXCEPTION_ILLEGAL_INSTRUCTION:
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
        case EXCEPTION_PRIV_INSTRUCTION:
        case EXCEPTION_IN_PAGE_ERROR:
        case EXCEPTION_DATATYPE_MISALIGNMENT:
        case EXCEPTION_NONCONTINUABLE_EXCEPTION:
            tf_v441::Reliability::CrashFlushAllTabs();
            break;
        default:
            break;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
#endif

// =============================================================================
//  WinMain
//  One accelerator table, created here, destroyed here.
// =============================================================================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    // v4.26: Capture the UI thread id BEFORE any window is created and BEFORE
    // any worker thread is spawned.  Every subsequent TF_AssertUIThread()
    // and TF_IsUIThread() check measures against this value.  All windows in
    // this app are created on this thread, so it uniquely identifies "the
    // thread allowed to call SendMessage / SetWindowText / Invalidate /
    // PieceTable mutators / undo-stack mutators".
    g_uiThreadId = ::GetCurrentThreadId();

#if !defined(_MSC_VER)
    // v4.41a: under GCC/MinGW the WindowProc wrapper cannot use SEH
    // (__try/__except).  Install a Vectored Exception Handler so hardware
    // faults still trigger CrashFlushAllTabs() before the OS terminates us.
    // First-call handler (1) so we run before any later-installed VEH.
    AddVectoredExceptionHandler(1, &Tf_CrashVEH);
#endif

    // 1. DPI Awareness (Per-Monitor V2)
    typedef BOOL(WINAPI* SetProcessDpiAwarenessContextFunc)(DPI_AWARENESS_CONTEXT);
    HMODULE hUser32 = GetModuleHandle(L"user32.dll");
    if (hUser32) {
        auto pSetDpi = (SetProcessDpiAwarenessContextFunc)
            GetProcAddress(hUser32, "SetProcessDpiAwarenessContext");
        if (pSetDpi) pSetDpi(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }

    // 2. Register Window Class
    const wchar_t CLASS_NAME[] = L"UniversalCodeEditor";
    HBRUSH hMainBackground = CreateSolidBrush(BG_COLOR);
    if (!hMainBackground) return 0;

    WNDCLASS wc      = { 0 };
    wc.lpfnWndProc   = WindowProc;
    wc.hInstance     = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = hMainBackground;

    if (!RegisterClass(&wc)) {
        if (hMainBackground) DeleteObject(hMainBackground);
        return 0;
    }

    // 3. Create Main Window
    HWND hwnd = CreateWindowEx(
        0, CLASS_NAME, L"Tiny Fantail",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 850, 600,
        NULL, NULL, hInstance, NULL);

    if (!hwnd) {
        if (hMainBackground) DeleteObject(hMainBackground);
        return 0;
    }

    // v4.26: publish the main window handle so worker threads can post UI
    // tasks via TF_PostUITask().  Release-store pairs with the
    // memory_order_acquire load inside TF_PostUITask.  This MUST happen
    // before any worker thread is spawned (workers begin life inside
    // SidebarOpenFile, BeginAsyncFileLoad, FileWatcherStart, all of which
    // run after the main message loop starts).
    g_hMainWnd.store(hwnd, std::memory_order_release);

    // 4. Single, consolidated accelerator table
    ACCEL accels[] = {
        { FCONTROL | FVIRTKEY,          'N',         IDM_FILE_NEW         },
        { FCONTROL | FVIRTKEY,          'O',         IDM_FILE_OPEN        },
        { FCONTROL | FVIRTKEY,          'S',         IDM_FILE_SAVE        },
        { FCONTROL | FSHIFT | FVIRTKEY, 'S',         IDM_FILE_SAVEAS      },
        { FCONTROL | FVIRTKEY,          'J',         IDM_EDIT_SELECT_J    },
        { FCONTROL | FVIRTKEY,          'R',         IDM_FOCUS_CMD        },
        { FCONTROL | FVIRTKEY,          'F',         IDM_FOCUS_SEARCH     },
        { FCONTROL | FVIRTKEY,          'U',         IDM_FOCUS_EDITOR     },
        { FCONTROL | FSHIFT | FVIRTKEY, 'R',         IDM_PURGE_TAB_RAM    },
        { FCONTROL | FVIRTKEY,          VK_OEM_6,    IDM_EDIT_INDENT      },
        { FCONTROL | FVIRTKEY,          VK_OEM_4,    IDM_EDIT_OUTDENT     },
        { FCONTROL | FVIRTKEY,          'I',         ID_GOTO_ERROR        },
        { FCONTROL | FVIRTKEY,          'K',         IDM_EDIT_MOVE_UP     },
        { FCONTROL | FVIRTKEY,          'L',         IDM_EDIT_MOVE_DOWN   },
        { FALT     | FVIRTKEY,          VK_UP,       IDM_EDIT_MOVE_UP     },
        { FALT     | FVIRTKEY,          VK_DOWN,     IDM_EDIT_MOVE_DOWN   },
        { FVIRTKEY,                     VK_F5,       IDC_CHECK_BTN        },
        { FVIRTKEY,                     VK_F6,       IDC_EXECUTE_BTN      },
        { FVIRTKEY,                     VK_F7,       IDM_EDIT_JUMP_SYMBOL },
        { FVIRTKEY,                     VK_F8,       ID_GOTO_ERROR        },
        { FCONTROL | FALT | FVIRTKEY,   'C',         IDM_EDIT_COMPACT     },
    };

    HACCEL hAccel = CreateAcceleratorTable(accels,
                        (int)(sizeof(accels) / sizeof(ACCEL)));

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    // v4.41 reliability hooks — surface any unsaved work from a previous
    // crashed session, then start the 30 s autosave heartbeat.
    tf_v441::Reliability::ScanForRecoverySnapshotsOnStartup(hwnd);
    tf_v441::Reliability::StartAutosaveTimer(hwnd);

    // 5. Message loop
    MSG msg = { 0 };
    while (GetMessage(&msg, NULL, 0, 0)) {
        if (hAccel && TranslateAccelerator(hwnd, hAccel, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // 6. Cleanup
    if (hAccel) { DestroyAcceleratorTable(hAccel); hAccel = NULL; }
    if (hMainBackground) { DeleteObject(hMainBackground); hMainBackground = NULL; }

    return (int)msg.wParam;
}
