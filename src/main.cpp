#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>
#include <algorithm>
#include <cmath>
#include <random>
#include <stdio.h>
#include <string>
#include <vector>
#include <visualizer.h>

struct Drop {
  float y;
  float speed;
  std::string glyphs;
};

static std::mt19937 rng{std::random_device{}()};

float randf(float a, float b) {
  return std::uniform_real_distribution<float>(a, b)(rng);
}

int randi(int a, int b) {
  return std::uniform_int_distribution<int>(a, b)(rng);
}

char randGlyph() {
  static const char set[] = "0123456789ABCDEF<>/\\|=+*#$%&";
  return set[randi(0, sizeof(set) - 2)];
}

static void resetDrop(Drop &d, float height, bool anywhere) {
  d.glyphs.resize(randi(8, 25));
  for (char &c : d.glyphs)
    c = randGlyph();
  d.speed = randf(80.0f, 250.0f);
  d.y = anywhere ? randf(0.0f, height) : -randf(0.0f, height * 0.5f);
}

// how to draw matrix rain (mad complicated)
static void drawRain(std::vector<Drop> &drops, float gapL, float gapR) {
  ImDrawList *dl = ImGui::GetWindowDrawList();
  ImVec2 pos = ImGui::GetWindowPos();
  ImVec2 size = ImGui::GetWindowSize();
  float charH = ImGui::GetFontSize();
  float charW = ImGui::CalcTextSize("W").x;
  float dt = ImGui::GetIO().DeltaTime;

  size_t cols = (size_t)(size.x / charW);
  if (drops.size() != cols) {
    drops.resize(cols);
    for (Drop &d : drops)
      resetDrop(d, size.y, true);
  }

  for (size_t i = 0; i < cols; i++) {
    float x = i * charW;
    if (x + charW > gapL && x < gapR)
      continue;

    Drop &d = drops[i];
    d.y += d.speed * dt;
    if (d.y - d.glyphs.size() * charH > size.y)
      resetDrop(d, size.y, false);
    for (char &c : d.glyphs)
      if (randf(0.0f, 1.0f) < dt * 3.0f)
        c = randGlyph();
    d.glyphs[randi(0, d.glyphs.size() - 1)] = randGlyph();

    for (size_t j = 0; j < d.glyphs.size(); j++) {
      float y = d.y - j * charH;
      if (y < -charH || y > size.y)
        continue;
      float fade = 1.0f - (float)j / d.glyphs.size();
      ImU32 col = j == 0 ? IM_COL32(255, 180, 180, 255)
                         : IM_COL32(220, 20, 30, (int)(fade * 220));
      char s[2] = {d.glyphs[j], '\0'};
      dl->AddText(ImVec2(pos.x + x, pos.y + y), col, s);
    }
  }
}

// opengl texture loader for logo image (kind of complicated also)
#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

GLuint loadTexture(const char *path, int &w, int &h) {
  unsigned char *data = stbi_load(path, &w, &h, nullptr, 4);
  if (!data)
    return 0;

  GLuint tex;
  glGenTextures(1, &tex);
  glBindTexture(GL_TEXTURE_2D, tex);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE,
               data);
  stbi_image_free(data);
  return tex;
}

struct LoadingScreen {
  GLuint open, closed;
  int texW, texH;
  float startTime;
};

static void drawLoading(LoadingScreen &ls) {
  ImDrawList *dl = ImGui::GetWindowDrawList();
  ImVec2 wp = ImGui::GetWindowPos();
  ImVec2 ws = ImGui::GetWindowSize();
  float t = (float)ImGui::GetTime() - ls.startTime;

  dl->AddRectFilled(wp, ImVec2(wp.x + ws.x, wp.y + ws.y),
                    IM_COL32(0, 0, 0, 255));

  ImGui::SetWindowFontScale(4.0f);
  float tw = ImGui::CalcTextSize("Loading...").x;
  int dots = (int)(t * 3.0f) % 4;
  std::string text = "Loading" + std::string(dots, '.');
  ImGui::SetCursorPos(ImVec2((ws.x - tw) * 0.5f, ws.y * 0.2f));
  ImGui::TextUnformatted(text.c_str());
  ImGui::SetWindowFontScale(1.0f);

  float jw = 192.0f, jh = 192.0f;
  float hopTime = 0.45f, hopDist = 120.0f, hopH = 40.0f;
  float mouth = 0.85f;
  float groundY = wp.y + ws.y * 0.6f;

  float loopW = std::ceil((ws.x + 2 * jw) / hopDist) * hopDist;
  int hop = (int)(t / hopTime);
  float phase = std::fmod(t, hopTime) / hopTime;
  float ease = phase * phase * (3.0f - 2.0f * phase);
  float travel = std::fmod(hop * hopDist + ease * hopDist, loopW);

  float startX = wp.x - jw;
  float x = startX + travel;
  float y = groundY - jh - std::sin(phase * 3.14159f) * hopH;
  float mouthX = x + jw * mouth;

  float block = 24.0f;
  float blockY = groundY - jh * 0.45f;
  for (float bx = startX + jw * mouth + hopDist; bx < wp.x + ws.x;
       bx += hopDist) {
    if (bx <= mouthX + 1.0f)
      continue;
    dl->AddRectFilled(ImVec2(bx - block * 0.5f, blockY - block * 0.5f),
                      ImVec2(bx + block * 0.5f, blockY + block * 0.5f),
                      IM_COL32(220, 20, 30, 255));
  }

  GLuint tex = phase < 0.7f ? ls.open : ls.closed;
  dl->AddImage((ImTextureID)(intptr_t)tex, ImVec2(x, y),
               ImVec2(x + jw, y + jh));
}

int main() {
  if (!glfwInit())
    return 1;

  glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
  glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
  glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

  GLFWwindow *window =
      glfwCreateWindow(1920, 1080, "hackjackal", nullptr, nullptr);
  if (!window)
    return 1;
  int iconW, iconH;
  unsigned char *iconPx =
      stbi_load("assets/mainjackal.png", &iconW, &iconH, nullptr, 4);
  if (iconPx) {
    GLFWimage icon{iconW, iconH, iconPx};
    glfwSetWindowIcon(window, 1, &icon);
    stbi_image_free(iconPx);
  }
  glfwMakeContextCurrent(window);
  glfwSwapInterval(1);

  ImGui::CreateContext();
  ImGui_ImplGlfw_InitForOpenGL(window, true);
  ImGui_ImplOpenGL3_Init("#version 330");

  int logoW, logoH;
  GLuint logo = loadTexture("assets/mainjackal.png", logoW, logoH);
  LoadingScreen loading{};
  loading.open =
      loadTexture("assets/open_mouth.png", loading.texW, loading.texH);
  loading.closed =
      loadTexture("assets/closed_mouth.png", loading.texW, loading.texH);
  Screen screen = Screen::Menu;
  Visualizer visualizer(loading.open, loading.closed);

  ImGuiStyle &s = ImGui::GetStyle();
  s.FrameRounding = 0.0f;
  s.FrameBorderSize = 1.0f;
  s.Colors[ImGuiCol_Button] = ImVec4(0.08f, 0.02f, 0.02f, 1.0f);
  s.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.45f, 0.05f, 0.08f, 1.0f);
  s.Colors[ImGuiCol_ButtonActive] = ImVec4(0.70f, 0.08f, 0.10f, 1.0f);
  s.Colors[ImGuiCol_Text] = ImVec4(0.95f, 0.85f, 0.85f, 1.0f);

  std::vector<Drop> drops;

  while (!glfwWindowShouldClose(window)) {
    glfwPollEvents();
    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();
    // menu UI

    const ImGuiViewport *vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGui::Begin("##main", nullptr,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                     ImGuiWindowFlags_NoSavedSettings |
                     ImGuiWindowFlags_NoBringToFrontOnFocus);

    if (screen == Screen::Menu) {
      float menuW = 450.0f;
      float gapL = (ImGui::GetWindowWidth() - menuW) * 0.5f;
      drawRain(drops, gapL, gapL + menuW);

      ImDrawList *dl = ImGui::GetWindowDrawList();
      ImVec2 p = ImGui::GetWindowPos();
      float h_rain = ImGui::GetWindowHeight();
      float x0 = p.x + gapL, x1 = p.x + gapL + menuW, f = 100.0f;

      ImU32 clear = IM_COL32(15, 15, 15, 0);
      ImU32 solid = IM_COL32(15, 15, 15, 255);
      dl->AddRectFilled(ImVec2(x0, p.y), ImVec2(x1, p.y + h_rain), solid);
      dl->AddRectFilledMultiColor(ImVec2(x0 - f, p.y), ImVec2(x0, p.y + h_rain),
                                  clear, solid, solid, clear);
      dl->AddRectFilledMultiColor(ImVec2(x1, p.y), ImVec2(x1 + f, p.y + h_rain),
                                  solid, clear, clear, solid);

      ImGui::SetWindowFontScale(5.0f);
      const char *title = "hackjackal";
      float tw = ImGui::CalcTextSize(title).x;
      ImGui::SetCursorPosY(ImGui::GetWindowHeight() * 0.1);
      ImGui::SetCursorPosX((ImGui::GetWindowWidth() - tw) * 0.5f);
      ImGui::Text("%s", title);

      // render logo image with distortion and flickering
      ImVec2 imgSize(logoW * 0.75f, logoH * 0.75f);
      ImGui::SetCursorPosX((ImGui::GetWindowWidth() - imgSize.x) * 0.5f);
      ImGui::SetCursorPosY(ImGui::GetWindowHeight() * 0.2f);
      ImVec2 p0 = ImGui::GetCursorScreenPos();
      ImVec2 p1(p0.x + imgSize.x, p0.y + imgSize.y);
      ImGui::Dummy(imgSize);

      ImTextureID logoId = (ImTextureID)(intptr_t)logo;
      float t = (float)ImGui::GetTime();

      for (int i = 1; i <= 10; i++)
        dl->AddRect(ImVec2(p0.x - i, p0.y - i), ImVec2(p1.x + i, p1.y + i),
                    IM_COL32(220, 20, 30, 120 / i));

      dl->AddImage(logoId, p0, p1, ImVec2(0, 0), ImVec2(1, 1),
                   IM_COL32(255, 255, 255, randi(225, 255)));

      float o = 2.0f + std::sin(t * 2.0f);
      dl->AddImage(logoId, ImVec2(p0.x - o, p0.y), ImVec2(p1.x - o, p1.y),
                   ImVec2(0, 0), ImVec2(1, 1), IM_COL32(255, 0, 40, 50));
      dl->AddImage(logoId, ImVec2(p0.x + o, p0.y), ImVec2(p1.x + o, p1.y),
                   ImVec2(0, 0), ImVec2(1, 1), IM_COL32(0, 220, 255, 40));

      if (randf(0.0f, 1.0f) < 0.03f) {
        int slices = randi(1, 3);
        for (int i = 0; i < slices; i++) {
          float v0 = randf(0.0f, 0.9f);
          float v1 = std::min(v0 + randf(0.02f, 0.1f), 1.0f);
          float off = randf(-15.0f, 15.0f);
          float y0 = p0.y + v0 * imgSize.y, y1 = p0.y + v1 * imgSize.y;
          dl->AddRectFilled(ImVec2(p0.x, y0), ImVec2(p1.x, y1), solid);
          dl->AddImage(logoId, ImVec2(p0.x + off, y0), ImVec2(p1.x + off, y1),
                       ImVec2(0, v0), ImVec2(1, v1));
        }
      }

      for (float sy = p0.y; sy < p1.y; sy += 3.0f)
        dl->AddLine(ImVec2(p0.x, sy), ImVec2(p1.x, sy), IM_COL32(0, 0, 0, 70));

      ImGui::SetWindowFontScale(1.0f);
      ImVec2 size(300, 60);
      float x = (ImGui::GetWindowWidth() - size.x) * 0.5f;
      float y = (ImGui::GetWindowHeight() - size.y) * 0.5f;

      auto button = [&](const char *label) {
        ImGui::SetCursorPosX(x);
        return ImGui::Button(label, size);
      };

      ImGui::SetCursorPosY(y * 1.3f);
      if (button("Start")) {
        screen = Screen::Loading;
        loading.startTime = (float)ImGui::GetTime();
        visualizer.startLoading("data");
        visualizer.beginReveal();
      }
      if (button("Credits")) {
        screen = Screen::Credits;
      }
      if (button("Github")) {
        ImGui::GetPlatformIO().Platform_OpenInShellFn(
            ImGui::GetCurrentContext(),
            "https://github.com/NikOffSec/hackjackal");
      }
      if (button("Quit"))
        glfwSetWindowShouldClose(window, true);
    } else if (screen == Screen::Credits) {
      const char *lines[] = {
          "This project was made by Niklas Ekebergh, Lethanial Leveille,",
          "and Nate Lacandazo based on what we learned in our",
          "Data Structures and Algorithms class.",
          "",
          "also shoutout to the goat Dr. Aman for being an amazing teacher",
          "and making us better computer scientists",
      };
      ImVec2 size(300, 60);
      float gap = 30.0f;
      float winW = ImGui::GetWindowWidth();
      float winH = ImGui::GetWindowHeight();

      ImGui::SetWindowFontScale(2.0f);
      float textH = IM_ARRAYSIZE(lines) * ImGui::GetTextLineHeightWithSpacing();
      ImGui::SetCursorPosY((winH - textH - gap - size.y) * 0.5f);
      for (const char *line : lines) {
        ImGui::SetCursorPosX((winW - ImGui::CalcTextSize(line).x) * 0.5f);
        ImGui::TextUnformatted(line);
      }
      ImGui::SetWindowFontScale(1.0f);

      ImGui::Dummy(ImVec2(0.0f, gap));
      ImGui::SetCursorPosX((winW - size.x) * 0.5f);
      if (ImGui::Button("Back", size) ||
          ImGui::IsKeyPressed(ImGuiKey_Escape, false))
        screen = Screen::Menu;
    } else if (screen == Screen::Loading) {
      drawLoading(loading);
      std::string status = visualizer.loadingStatus();
      ImGui::SetCursorPos(ImVec2(
          (ImGui::GetWindowWidth() - ImGui::CalcTextSize(status.c_str()).x) *
              0.5f,
          ImGui::GetWindowHeight() * 0.3f));
      ImGui::TextUnformatted(status.c_str());
      // stay a little even if the data is quick so the animation gets seen,
      // the first 1.5 seconds or so are still decrypting
      if (visualizer.loadingDone() &&
          (float)ImGui::GetTime() - loading.startTime > 3.0f) {
        screen = Screen::Idle;
        visualizer.beginReveal();
      }
    } else {
      visualizer.draw(screen);
    }

    ImGui::End();
    visualizer.drawWindows(screen);

    ImGui::Render();
    int w, h;
    glfwGetFramebufferSize(window, &w, &h);
    glViewport(0, 0, w, h);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    glfwSwapBuffers(window);
  }

  glDeleteTextures(1, &logo);
  glDeleteTextures(1, &loading.open);
  glDeleteTextures(1, &loading.closed);
  ImGui_ImplOpenGL3_Shutdown();
  ImGui_ImplGlfw_Shutdown();
  ImGui::DestroyContext();
  glfwDestroyWindow(window);
  glfwTerminate();
}
