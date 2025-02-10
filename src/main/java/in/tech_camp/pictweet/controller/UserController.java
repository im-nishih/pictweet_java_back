package in.tech_camp.pictweet.controller;

import org.springframework.web.bind.annotation.GetMapping;
// import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.http.ResponseEntity;
// import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import in.tech_camp.pictweet.entity.TweetEntity;
import in.tech_camp.pictweet.entity.UserEntity;
import in.tech_camp.pictweet.form.UserForm;
import in.tech_camp.pictweet.repository.UserRepository;
import in.tech_camp.pictweet.service.UserService;
import in.tech_camp.pictweet.validation.ValidationOrder;
import lombok.AllArgsConstructor;

@RestController
//"/api/users/～"からのURLとする。
@RequestMapping("/api/users")
@AllArgsConstructor
public class UserController {

  private final UserRepository userRepository;

  private final UserService userService;

  // @GetMapping("/users/sign_up")
  // public String showSignUp(Model model){
  //   model.addAttribute("userForm", new UserForm());
  //   return "users/signUp";
  // }

  //User新規作成処理
  @PostMapping("/")
  public ResponseEntity<?> createUser(@RequestBody @Validated(ValidationOrder.class) UserForm userForm, BindingResult result) {
    userForm.validatePasswordConfirmation(result);
    //メールアドレス存在チェック
    if (userRepository.existsByEmail(userForm.getEmail())) {
      result.rejectValue("email", "null", "Email already exists");
    }

    //エラーの場合badRequest
    if (result.hasErrors()) {
      List<String> errorMessages = result.getAllErrors().stream()
              .map(DefaultMessageSourceResolvable::getDefaultMessage)
              .collect(Collectors.toList());

      return ResponseEntity.badRequest().body(Map.of("messages", errorMessages));
      
      // model.addAttribute("errorMessages", errorMessages);
      // model.addAttribute("userForm", userForm);
      // return "users/signUp";
    }

    //userFormの情報をuserEntityにセット
    UserEntity userEntity = new UserEntity();
    userEntity.setNickname(userForm.getNickname());
    userEntity.setEmail(userForm.getEmail());
    userEntity.setPassword(userForm.getPassword());

    try {
      //ユーザ情報Insert
      userService.createUserWithEncryptedPassword(userEntity);
      //idとNicknameを返す
      return ResponseEntity.ok().body(Map.of(
        "id", userEntity.getId(),
        "nickname", userEntity.getNickname()
      ));
    } catch (Exception e) {
      System.out.println("エラー：" + e);
      return ResponseEntity.internalServerError().body(Map.of("messages", List.of("Internal Server Error")));
      // return "redirect:/";
    }

    // return "redirect:/";
  }

  //マイページ画面
  @GetMapping("/{userId}")
  public ResponseEntity<UserEntity> showMypage(@PathVariable("userId") Integer userId) {
    //ユーザ取得
    UserEntity user = userRepository.findById(userId);

    if (user == null) {
      return ResponseEntity.notFound().build();
    }

    return ResponseEntity.ok().body(user);
  }

  // @GetMapping("/users/login")
  // public String showLogin(){
  //     return "users/login";
  // }

  // @GetMapping("/login")
  // public String showLoginWithError(@RequestParam(value = "error") String error, Model model) {
  //   if (error != null) {
  //     model.addAttribute("loginError", "Invalid email or password.");
  //   }
  //   return "users/login";
  // }

  // @GetMapping("/users/{userId}")
  // public String showMypage(@PathVariable("userId") Integer userId, Model model) {
  //   UserEntity user = userRepository.findById(userId);
  //   List<TweetEntity> tweets = user.getTweets();

  //   model.addAttribute("nickname", user.getNickname());
  //   model.addAttribute("tweets", tweets);
  //   return "users/mypage";
  // }
}
