package handle

import (
	"regexp"
	"strings"
	"testing"

	"github.com/deepflowio/deepflow/server/mcp/config"
	"github.com/deepflowio/deepflow/server/mcp/model"
)

var (
	nodeLineRe = regexp.MustCompile(`^(func\d+)\["\[[^\]]*\] ([A-Za-z0-9_]+)\\\(`)
	edgeLineRe = regexp.MustCompile(`^(func\d+) --> (func\d+)$`)
)

// edgesByFunctionName parses the rendered mermaid graph into caller->callee
// pairs of function names, so assertions do not depend on the ordering that
// the total-time sort happens to produce.
func edgesByFunctionName(t *testing.T, diagram string) map[string]bool {
	t.Helper()
	idToName := make(map[string]string)
	edges := make(map[string]bool)
	var pending [][2]string
	for _, line := range strings.Split(diagram, "\n") {
		line = strings.TrimSpace(line)
		if m := nodeLineRe.FindStringSubmatch(line); m != nil {
			idToName[m[1]] = m[2]
			continue
		}
		if m := edgeLineRe.FindStringSubmatch(line); m != nil {
			pending = append(pending, [2]string{m[1], m[2]})
		}
	}
	for _, pair := range pending {
		caller, okCaller := idToName[pair[0]]
		callee, okCallee := idToName[pair[1]]
		if !okCaller || !okCallee {
			t.Fatalf("edge references an undeclared node: %s --> %s", pair[0], pair[1])
		}
		edges[caller+"->"+callee] = true
	}
	return edges
}

// node_values rows are [function_id, parent_node_id, self_value, total_value].
// parent_node_id indexes the row order of node_values, while function_id
// indexes the functions slice. The two diverge as soon as one function owns
// more than one node, which is the normal case for a call graph where the same
// callee is reached from several stacks.
func TestDiagramResolvesParentThroughNodeIndex(t *testing.T) {
	profileData := &model.ProfileData{
		FunctionTypes: []string{"t", "t", "t", "t"},
		FunctionNames: []string{"rootFn()", "alphaFn()", "betaFn()", "gammaFn()"},
		FunctionValues: model.DataFrame{
			Columns: []string{"self_value", "total_value"},
			Values: [][]interface{}{
				{0, 100},
				{40, 100},
				{0, 0},
				{30, 30},
			},
		},
		NodeValues: model.DataFrame{
			Columns: []string{"function_id", "parent_node_id", "self_value", "total_value"},
			Values: [][]interface{}{
				{0, -1, 0, 100}, // node 0: rootFn, root of the graph
				{1, 0, 0, 60},   // node 1: alphaFn, called by node 0
				{1, 0, 40, 40},  // node 2: alphaFn again, a second stack
				{3, 2, 30, 30},  // node 3: gammaFn, called by node 2 (alphaFn)
			},
		},
	}

	edges := edgesByFunctionName(t, generateFunctionMermaidDiagram(profileData))

	if !edges["alphaFn->gammaFn"] {
		t.Errorf("want edge alphaFn->gammaFn (parent node 2 is alphaFn), got edges: %v", edges)
	}
	if edges["betaFn->gammaFn"] {
		t.Errorf("gammaFn must not be attributed to betaFn; edges: %v", edges)
	}
}

// The linear stack keeps node index equal to function id; it guards the fix
// against changing behaviour on the shape that already worked.
func TestDiagramKeepsLinearStackEdges(t *testing.T) {
	profileData := &model.ProfileData{
		FunctionTypes: []string{"t", "t", "t"},
		FunctionNames: []string{"rootFn()", "alphaFn()", "betaFn()"},
		FunctionValues: model.DataFrame{
			Columns: []string{"self_value", "total_value"},
			Values: [][]interface{}{
				{0, 100},
				{0, 60},
				{60, 60},
			},
		},
		NodeValues: model.DataFrame{
			Columns: []string{"function_id", "parent_node_id", "self_value", "total_value"},
			Values: [][]interface{}{
				{0, -1, 0, 100},
				{1, 0, 0, 60},
				{2, 1, 60, 60},
			},
		},
	}

	edges := edgesByFunctionName(t, generateFunctionMermaidDiagram(profileData))

	if !edges["rootFn->alphaFn"] || !edges["alphaFn->betaFn"] {
		t.Errorf("want rootFn->alphaFn and alphaFn->betaFn, got edges: %v", edges)
	}
	if len(edges) != 2 {
		t.Errorf("want exactly 2 edges, got %d: %v", len(edges), edges)
	}
}

// The legend line used to pass the translated template as an argument to an
// unrelated format string, so the counts never reached the output and Sprintf
// appended an %!(EXTRA ...) marker.
func TestDiagramLegendCarriesCounts(t *testing.T) {
	profileData := &model.ProfileData{
		FunctionTypes:  []string{"t", "t"},
		FunctionNames:  []string{"rootFn()", "alphaFn()"},
		FunctionValues: model.DataFrame{Columns: []string{"self_value", "total_value"}, Values: [][]interface{}{{0, 10}, {10, 10}}},
		NodeValues: model.DataFrame{
			Columns: []string{"function_id", "parent_node_id", "self_value", "total_value"},
			Values:  [][]interface{}{{0, -1, 0, 10}, {1, 0, 10, 10}},
		},
	}

	prevConfig := config.MConfig
	config.MConfig = nil
	t.Cleanup(func() { config.MConfig = prevConfig })

	diagram := generateFunctionMermaidDiagram(profileData)

	if strings.Contains(diagram, "%!") {
		t.Errorf("legend contains Sprintf error markers:/n%s", diagram)
	}
	if !strings.Contains(diagram, `info["显示了 2 个函数，1 条调用关系"]`) {
		t.Errorf("legend does not carry the counts, got:/n%s", diagram)
	}
}
