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

// Post is one blog entry; HTML is trusted because posts are our own committed content.
type Post struct {
	Slug  string
	Title string
	Date  time.Time
	Desc  string
	Image string
	Draft bool
	HTML  template.HTML
	// Markdown is the body as written, frontmatter stripped; kept out of REST JSON.
	Markdown string `json:"-"`
}

// DateLayout is the frontmatter date format; an unquoted date becomes a YAML time.Time and fails the load.
const DateLayout = "2006-01-02"

// md: goldmark-meta parses frontmatter; Linkify links bare https:// URLs, which posts cite constantly.
var md = goldmark.New(goldmark.WithExtensions(meta.Meta, extension.Linkify))

// LoadPosts skips drafts, sorts newest first, and fails whole on one malformed post (fatal at prod boot).
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
		Slug:     slugFromFilename(p),
		Title:    title,
		Date:     date,
		Desc:     metaString(m, "description"),
		Image:    metaString(m, "image"),
		Draft:    m["draft"] == true,
		HTML:     template.HTML(buf.String()),
		Markdown: stripFrontmatter(src),
	}, nil
}

// stripFrontmatter drops the leading "---" block every post opens with.
func stripFrontmatter(src []byte) string {
	if rest, ok := bytes.CutPrefix(src, []byte("---\n")); ok {
		if _, body, ok := bytes.Cut(rest, []byte("\n---\n")); ok {
			return strings.TrimLeft(string(body), "\n")
		}
	}
	return string(src)
}

// slugFromFilename: "2026-07-28-some-title.md" → "some-title"; no date prefix keeps the whole basename.
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

func metaDate(m map[string]any) (time.Time, error) {
	v, ok := m["date"].(string)
	if !ok {
		return time.Time{}, fmt.Errorf("frontmatter missing or invalid date")
	}
	return time.Parse(DateLayout, v)
}
