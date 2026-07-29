package cmd

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"

	"github.com/apoxy-dev/apoxy/pkg/cmd/utils"
)

// deployStatus renders deploy progress as a compact step list: a spinner on
// the step in flight, then a green check or red cross once it settles, with
// the step's outcome (generated names, written files, digests) on the same
// line so nothing happens invisibly. When the session is not interactive it
// degrades to plain sequential lines, and if the interactive renderer dies
// mid-deploy (terminal init failure, interrupt) Close replays the full step
// list as plain lines so the record — digest included — is never lost.
type deployStatus struct {
	out   io.Writer
	plain bool

	prog   *tea.Program
	done   chan struct{}
	runErr error // written by the render goroutine before done is closed

	mu    sync.Mutex
	steps []deployStep
}

func newDeployStatus(out io.Writer) *deployStatus {
	f, ok := out.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) || !utils.IsInteractive() {
		return &deployStatus{out: out, plain: true}
	}
	// No bubbletea signal handler: SIGINT is owned by main's context cancel,
	// which aborts the in-flight step and unwinds through Close normally.
	p := tea.NewProgram(newDeployStatusModel(),
		tea.WithOutput(f), tea.WithInput(nil), tea.WithoutSignalHandler())
	ds := &deployStatus{out: out, prog: p, done: make(chan struct{})}
	go func() {
		_, ds.runErr = p.Run()
		close(ds.done)
	}()
	return ds
}

// alive reports whether the render goroutine is still running.
func (s *deployStatus) alive() bool {
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

// Start begins a new step. The previous step must have been settled with
// Done or Fail first.
func (s *deployStatus) Start(label string) {
	s.mu.Lock()
	s.steps = append(s.steps, deployStep{label: label, state: deployStepRunning})
	s.mu.Unlock()
	if !s.plain && s.alive() {
		s.prog.Send(deployStepStartMsg{label: label})
	}
}

// Done settles the current step successfully; detail says what was produced.
func (s *deployStatus) Done(detail string) {
	s.settle(deployStepOK, detail, deployStepDoneMsg{detail: detail})
}

// Fail settles the current step as failed. The error itself is returned to
// cobra by the caller; the step line only marks where the flow stopped.
func (s *deployStatus) Fail() {
	s.settle(deployStepFailed, "", deployStepFailMsg{})
}

func (s *deployStatus) settle(state deployStepState, detail string, msg tea.Msg) {
	s.mu.Lock()
	var st deployStep
	if n := len(s.steps); n > 0 {
		s.steps[n-1].state = state
		s.steps[n-1].detail = detail
		st = s.steps[n-1]
	}
	s.mu.Unlock()
	if s.plain {
		fmt.Fprintln(s.out, plainStepLine(st))
		return
	}
	if s.alive() {
		s.prog.Send(msg)
	}
}

// Close stops the renderer, leaving the final step list on screen. If the
// interactive renderer exited abnormally, the settled step list is replayed
// as plain lines so the outcome of every step is still on record.
func (s *deployStatus) Close() {
	if s.plain {
		return
	}
	if s.alive() {
		s.prog.Send(deployStatusQuitMsg{})
	}
	<-s.done
	if s.runErr == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range s.steps {
		fmt.Fprintln(s.out, plainStepLine(st))
	}
}

// plainStepLine renders one settled (or abandoned in-flight) step as an
// unstyled line.
func plainStepLine(st deployStep) string {
	icon := "…"
	switch st.state {
	case deployStepOK:
		icon = "✓"
	case deployStepFailed:
		icon = "✗"
	}
	return fmt.Sprintf("%s %-16s %s", icon, st.label, st.detail)
}

type deployStepState int

const (
	deployStepRunning deployStepState = iota
	deployStepOK
	deployStepFailed
)

type deployStep struct {
	label  string
	detail string
	state  deployStepState
}

type (
	deployStepStartMsg  struct{ label string }
	deployStepDoneMsg   struct{ detail string }
	deployStepFailMsg   struct{}
	deployStatusQuitMsg struct{}
)

type deployStatusModel struct {
	spinner spinner.Model
	steps   []deployStep
	width   int
}

func newDeployStatusModel() deployStatusModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	return deployStatusModel{spinner: s}
}

func (m deployStatusModel) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m deployStatusModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case deployStepStartMsg:
		m.steps = append(m.steps, deployStep{label: msg.label, state: deployStepRunning})
		return m, nil
	case deployStepDoneMsg:
		if n := len(m.steps); n > 0 {
			m.steps[n-1].state = deployStepOK
			m.steps[n-1].detail = msg.detail
		}
		return m, nil
	case deployStepFailMsg:
		if n := len(m.steps); n > 0 {
			m.steps[n-1].state = deployStepFailed
		}
		return m, nil
	case deployStatusQuitMsg:
		return m, tea.Quit
	}
	return m, nil
}

func (m deployStatusModel) View() string {
	var out string
	for _, st := range m.steps {
		var icon string
		switch st.state {
		case deployStepRunning:
			icon = m.spinner.View()
		case deployStepOK:
			icon = styleCreate.Render("✓")
		case deployStepFailed:
			icon = styleError.Render("✗")
		}
		line := fmt.Sprintf("%s %-16s %s", icon, st.label, styleUnchanged.Render(st.detail))
		if m.width > 0 {
			// Wrap instead of letting the renderer truncate: long details
			// (bundle digests) must stay fully visible.
			line = lipgloss.NewStyle().Width(m.width).Render(line)
		}
		out += line + "\n"
	}
	return out
}
