<?php

namespace LoginWithPhone\Controller\Front;

use Front\Front;
use LoginWithPhone\Form\Front\CustomerLogin;
use LoginWithPhone\Security\Authentication\CustomerUsernamePasswordFormAuthenticator;
use Thelia\Core\Event\Customer\CustomerEvent;
use Thelia\Core\Event\TheliaEvents;
use Thelia\Core\Security\Exception\AuthenticationException;
use Thelia\Core\Security\Exception\CustomerNotConfirmedException;
use Thelia\Core\Security\Exception\UsernameNotFoundException;
use Thelia\Core\Security\Exception\WrongPasswordException;
use Thelia\Form\Exception\FormValidationException;
use Thelia\Log\Tlog;
use Thelia\Model\Customer;

class CustomerController extends \Front\Controller\CustomerController
{
    /**
     * Perform user login. On a successful login, the user is redirected to the URL
     * found in the success_url form parameter, or / if none was found.
     *
     * If login is not successfull, the same view is displayed again.
     *
     */
    public function loginAction()
    {
        if (!$this->getSecurityContext()->hasCustomerUser()) {
            $request = $this->getRequest();
            $customerLoginForm = new CustomerLogin($request);

            try {
                $form = $this->validateForm($customerLoginForm, "post");

                // If User is a new customer
                if ($form->get('account')->getData() == 0 && $form->get("email")->getErrors()->count() == 0) {
                    return $this->generateRedirectFromRoute(
                        "customer.create.process",
                        ["email" => $form->get("email")->getData()]
                    );
                } else {
                    try {
                        $authenticator = new CustomerUsernamePasswordFormAuthenticator($request, $customerLoginForm, [
                            'username_field_name' => 'email'
                        ]);

                        /** @var Customer $customer */
                        $customer = $authenticator->getAuthentifiedUser();

                        $this->processLogin($customer);

                        if (intval($form->get('remember_me')->getData()) > 0) {
                            // If a remember me field if present and set in the form, create
                            // the cookie thant store "remember me" information
                            $this->createRememberMeCookie(
                                $customer,
                                $this->getRememberMeCookieName(),
                                $this->getRememberMeCookieExpiration()
                            );
                        }

                        return $this->generateSuccessRedirect($customerLoginForm);

                    } catch (UsernameNotFoundException $e) {
                        $message = $this->getTranslator()->trans(
                            "Wrong email or password. Please try again",
                            [],
                            Front::MESSAGE_DOMAIN
                        );
                    } catch (WrongPasswordException $e) {
                        $message = $this->getTranslator()->trans(
                            "Wrong email or password. Please try again",
                            [],
                            Front::MESSAGE_DOMAIN
                        );
                    } catch (CustomerNotConfirmedException $e) {
                        if ($e->getUser() !== null) {
                            // Send the confirmation email again
                            $this->getDispatcher()->dispatch(
                                TheliaEvents::SEND_ACCOUNT_CONFIRMATION_EMAIL,
                                new CustomerEvent($e->getUser())
                            );
                        }
                        $message = $this->getTranslator()->trans(
                            "Your account is not yet confirmed. A confirmation email has been sent to your email address, please check your mailbox",
                            [],
                            Front::MESSAGE_DOMAIN
                        );
                    } catch (AuthenticationException $e) {
                        $message = $this->getTranslator()->trans(
                            "Wrong email or password. Please try again",
                            [],
                            Front::MESSAGE_DOMAIN
                        );
                    }

                }
            } catch (FormValidationException $e) {
                $message = $this->getTranslator()->trans(
                    "Please check your input: %s",
                    ['%s' => $e->getMessage()],
                    Front::MESSAGE_DOMAIN
                );
            } catch (\Exception $e) {
                $message = $this->getTranslator()->trans(
                    "Sorry, an error occured: %s",
                    ['%s' => $e->getMessage()],
                    Front::MESSAGE_DOMAIN
                );
            }

            Tlog::getInstance()->error(
                sprintf(
                    "Error during customer login process : %s. Exception was %s",
                    $message,
                    $e->getMessage()
                )
            );

            $customerLoginForm->setErrorMessage($message);

            $this->getParserContext()->addForm($customerLoginForm);

            if ($customerLoginForm->hasErrorUrl()) {
                return $this->generateErrorRedirect($customerLoginForm);
            }
        }
    }
}
