package site

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/yuin/goldmark"
	meta "github.com/yuin/goldmark-meta"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
)

// Post: one blog entry, rendered from a markdown file in posts/.
// HTML is trusted — posts are our own committed content.
// Image: optional frontmatter `image` — a site path ("/static/img/x.png")
// or absolute URL used as the post's og:image instead of the default cover.
type Post struct {
	Slug  string
	Title string
	Date  time.Time
	Desc  string
	Image string
	Draft bool
	HTML  template.HTML
}

// DateLayout: frontmatter `date` format. Dates must be quoted in frontmatter
// ("2026-07-28") — unquoted dates (YAML hands us a time.Time) are a load error.
const DateLayout = "2006-01-02"

// md renders every post body; goldmark-meta parses the YAML frontmatter,
// Linkify turns bare https:// URLs into links (posts cite them constantly).
var md = goldmark.New(goldmark.WithExtensions(meta.Meta, extension.Linkify))

// LoadPosts parses every *.md at fsys root into Posts: frontmatter → fields,
// body → HTML, slug from filename. Drafts filtered, rest sorted by date
// descending. Any malformed post fails the whole load — caller decides
// (prod boot = fatal; better a refused deploy than a half-broken blog).
func LoadPosts(fsys fs.FS) ([]Post, error) {
	var posts []Post
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".md") {
			return nil
		}
		post, err := parsePost(fsys, p)
		if err != nil {
			return fmt.Errorf("blog post %s: %w", p, err)
		}
		if !post.Draft {
			posts = append(posts, post)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(posts, func(a, b Post) int { return b.Date.Compare(a.Date) })
	return posts, nil
}

// parsePost renders one markdown file into a Post.
func parsePost(fsys fs.FS, p string) (Post, error) {
	src, err := fs.ReadFile(fsys, p)
	if err != nil {
		return Post{}, err
	}
	var buf bytes.Buffer
	ctx := parser.NewContext()
	if err := md.Convert(src, &buf, parser.WithContext(ctx)); err != nil {
		return Post{}, err
	}
	m := meta.Get(ctx)
	title := metaString(m, "title")
	if title == "" {
		return Post{}, fmt.Errorf("frontmatter missing title")
	}
	date, err := metaDate(m)
	if err != nil {
		return Post{}, err
	}
	return Post{
		Slug:  slugFromFilename(p),
		Title: title,
		Date:  date,
		Desc:  metaString(m, "description"),
		Image: metaString(m, "image"),
		Draft: m["draft"] == true,
		HTML:  template.HTML(buf.String()),
	}, nil
}

// slugFromFilename: "2026-07-28-some-title.md" → "some-title"; a file with no
// date prefix keeps its whole basename.
func slugFromFilename(p string) string {
	base := strings.TrimSuffix(path.Base(p), ".md")
	if len(base) > len(DateLayout)+1 {
		if _, err := time.Parse(DateLayout, base[:len(DateLayout)]); err == nil && base[len(DateLayout)] == '-' {
			return base[len(DateLayout)+1:]
		}
	}
	return base
}

func metaString(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// metaDate requires the house format: quoted "YYYY-MM-DD" string.
// Unquoted dates (YAML hands us a time.Time) fail fast like any other
// malformed frontmatter.
func metaDate(m map[string]any) (time.Time, error) {
	v, ok := m["date"].(string)
	if !ok {
		return time.Time{}, fmt.Errorf("frontmatter missing or invalid date")
	}
	return time.Parse(DateLayout, v)
}
