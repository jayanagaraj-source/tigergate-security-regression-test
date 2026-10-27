package com.example.regression;

import java.io.IOException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/** JAVA-011 positives: request data concatenated into servlet HTML output without full escaping. */
public class ReflectingServlet extends HttpServlet {

    protected void greet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.getWriter().println("<h1>Hello " + req.getParameter("name") + "</h1>"); // JAVA-XSS-TP-001
    }

    protected void comment(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String body = req.getParameter("body");
        resp.getWriter().write("<p>" + body + "</p>"); // JAVA-XSS-TP-002
    }

    protected void referer(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.getWriter().print("<div>Back to " + req.getHeader("Referer")); // JAVA-XSS-TP-003
    }

    protected void partialEscape(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String title = req.getParameter("title").replace("<", "&lt;").replace(">", "&gt;");
        resp.getWriter().println("<a title=\"" + title + "\">link</a>"); // JAVA-XSS-TP-004
    }

    protected void query(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.getWriter().append("<b>" + req.getQueryString() + "</b>"); // JAVA-XSS-TP-005
    }

    protected void wrongOrder(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String v = req.getParameter("v").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("&", "&amp;");
        resp.getWriter().println("<span>" + v + "</span>"); // JAVA-XSS-TP-006
    }

    protected void stream(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.getOutputStream().print("<i>" + req.getParameter("note") + "</i>"); // JAVA-XSS-TP-007
    }

    protected void results(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String q = req.getParameter("q");
        resp.getWriter().println("Results for " + q); // JAVA-XSS-TP-008
    }

    protected void cookie(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Cookie c = req.getCookies()[0];
        resp.getWriter().write("<span>" + c.getValue() + "</span>"); // JAVA-XSS-TP-009
    }

    protected void suffix(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.getWriter().println(req.getParameter("lead") + " wrote this"); // JAVA-XSS-TP-010
    }

    protected void viaWriterVariable(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        java.io.PrintWriter out = resp.getWriter();
        out.println("<p>" + req.getParameter("msg") + "</p>"); // JAVA-XSS-GAP-001
    }

    protected void noConcatenation(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.getWriter().println(req.getParameter("raw")); // JAVA-XSS-GAP-002
    }
}
